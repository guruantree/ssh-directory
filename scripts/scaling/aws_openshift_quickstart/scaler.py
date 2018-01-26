#!/usr/bin/env python
import ConfigParser
import argparse
import os
import subprocess
import tempfile
import shlex
import time
from aws_openshift_quickstart.utils import *
from aws_openshift_quickstart.logger import LogUtil
LogUtil.set_log_handler('/var/log/openshift-quickstart-scaling.log')
log = LogUtil.get_root_logger()

def generate_inital_inventory_nodes():
    """
    Generates the initial ansible inventory. Instances only.
    """

    # Need to have the masters placed in the nodes section as well
    for group in ClusterGroups.groups:
        if group.openshift_config_category == 'masters':
            masters = group.node_hostdefs

    for group in ClusterGroups.groups:
        with open('/tmp/openshift_ansible_inventory_{}'.format(group.openshift_config_category), 'w') as f:
            f.write('[{}]\n'.format(group.openshift_config_category))

            if group.openshift_config_category == 'nodes':
                f.write('\n'.join(masters))
                f.write('\n')

            f.write('\n'.join(group.node_hostdefs))
            f.write('\n\n')
    return True

def scale_inventory_groups():
    """
    Processes the scaling activities.
    - Fires off the ansible playbook if needed.
    - Prunes the ansible inventory to remove instances that have scaled down / terminated.
    """
    c = InventoryConfig.c

    #First, we just make sure that there's *something* to add/remove.
    api_state = False
    attempts = 0
    total_scaled_nodes = []
    log.info("Verifying that the API reflects the scaling events properly")
    while api_state == False:
      for group in ClusterGroups.groups:
        total_scaled_nodes += group.scale_in_progress_instances['terminate']
        total_scaled_nodes += group.scale_in_progress_instances['launch']
      if attempts > 12:
        log.info("No scaling events were populated. 2 minute timer expired. Moving on...")
        break
      if len(total_scaled_nodes) == 0:
        time.sleep(10)
        ClusterGroups.setup()
        attempts +=1
      else:
        log.info("Great! The API contains scaling events that we need to process!")
        api_state = True

    _is = InventoryScaling
    scaleup_needed = False
    for group in ClusterGroups.groups:
        if (not group.scale_override) and (not group.scaling_events):
            continue
        # Here we add the instance IDs to the termination and launchlist.
        _is.nodes_to_remove[group.logical_name] += group.scale_in_progress_instances['terminate']
        _is.nodes_to_add[group.logical_name] += group.scale_in_progress_instances['launch']

        # duplicate this to the combined list.
        _is.nodes_to_add['combined'] += _is.nodes_to_add[group.logical_name]
        _is.nodes_to_remove['combined'] += _is.nodes_to_remove[group.logical_name]

    # We wait for the API to populate with the new instance IDs.
    if _is.nodes_to_add['combined']:
        scaleup_needed=True
        _is.wait_for_api()

    # Now we convert the IDs in each list to IP Addresses.
    for e in _is.nodes_to_add.keys():
        _templist = []
        for instance_id in _is.nodes_to_add[e]:
            _templist.append(InventoryConfig.provisioning_hostdefs[instance_id])
        _is.nodes_to_add[e] = _templist

    for e in _is.nodes_to_remove.keys():
        _templist = []
        for instance_id in _is.nodes_to_remove[e]:
            try:
                _templist.append(InventoryConfig.known_instances[instance_id])
            except KeyError:
                continue
        _is.nodes_to_remove[e] = _templist

    # For the moment, master scaleup'd hosts need to be in both
    #   - new_masters
    #   - new_nodes
    # This statement accomplishes that. More code below to prune out before running the playbook.
    if _is.nodes_to_add['masters']:
      _is.nodes_to_add['nodes'] += _is.nodes_to_add['masters']

    _is.process_pipeline()
    with open(InventoryConfig.inventory_file,'w') as f:
        c.write(EqualsSpaceRemover(f))

    # See note above about new_masters/new_nodes; This weeds those out.
    _n = _is.nodes_to_add['masters']
    _m = _is.nodes_to_add['nodes']
    for host in _m:
      if host in _n:
       del _is.nodes_to_add['nodes'][_n.index(host)]

    # If we need to scale up, then run the ansible playbook.
    if scaleup_needed:
        log.info("We've detected that we need to run ansible playbooks to scale up the cluster!")
        ansible_commands = {}
        proc_cat = {}
        file_cat = {}
        completed_numproc = 0
        completed_procs = []
        for category in InventoryConfig._inventory_node_skel.keys():
            if category is 'provision':
                continue
            if category is 'etcd':
              _is_cat_name = category
            else:
              _is_cat_name = "{}{}".format(category, 's')
            # categories are plural in the nodes_to_add dict, singular in everything else.
            if len(_is.nodes_to_add[_is_cat_name]) == 0:
                continue
            provisioning_category = InventoryConfig.inventory_categories['provision'][0]
            _extra_vars = '{}"{}"'.format('--extra-vars=', str({"target": provisioning_category, "scaling_category": category}))
            _ansible_cmd = "{} {} {}".format(
                "ansible-playbook",
                InventoryConfig.ansible_playbook_wrapper,
                _extra_vars
		)
            log.info("We will run the following ansible command:")
            log.info(_ansible_cmd)
            ansible_commands[_is_cat_name] = _ansible_cmd
        FNULL = open(os.devnull, 'w')
        for category in ansible_commands.keys():
            command = ansible_commands[category]
            stdout_tempfile = tempfile.mkstemp()[1]
            with open(stdout_tempfile, 'w') as fileout:
                process = subprocess.Popen(shlex.split(command), stdout=fileout, stderr=FNULL)
                proc_cat[category] = process
                file_cat[category] = stdout_tempfile
        numcats = len(proc_cat.keys())
        log.info("We have {} ansible playbooks running!".format(numcats))
        while True:
            if numcats == completed_numproc:
                break
            for cat in proc_cat.keys():
                p = proc_cat[cat]
                if p in completed_procs:
                    continue
                if p.poll() is not None:
                    log.info("- A process completed. We're parsing it...")
                    _is.process_playbook_json_output(jout_file=file_cat[cat], category=cat)
                    completed_procs.append(p)
                    completed_numproc += 1
                    log.info("- complete! We have {} to go...".format((numcats - completed_numproc)))
        # Now we do the necessary on the results.
        for cat in _is.ansible_results.keys():
            cjson = _is.ansible_results[cat]
            log.info("Category: {}, Results: {} / {} / {}, ({} / {} / {})".format(
                    cat, len(cjson['succeeded']), len(cjson['failed']), len(cjson['unreachable']), 'Succeeded','Unreachable','Failed'))
            _is.migrate_nodes_between_section(cjson['succeeded'], cat)
        with open('/etc/ansible/hosts', 'w') as cfile:
          c.write(EqualsSpaceRemover(cfile))

def main():
    log.info("--------- Begin Script Invocation ---------")
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--generate-initial-inventory', help='Generate the initial nodelist and populate the Ansible Inventory File', action='store_true')
    parser.add_argument('--scale-in-progress', help='Indicate that a Scaling Action is in progress in at least one cluster Auto Scaling Group', action='store_true')
    args = parser.parse_args()

    if args.debug:
      log.info("Enabling loglevel DEBUG...")
      log.handlers[0].setLevel(10)
      log.debug("enabled!")


    log.debug("Passed arguments: {} ".format(args.__dict__))
    InventoryConfig.setup()
    InventoryConfig.c = ConfigParser.ConfigParser(allow_no_value=True)
    InventoryConfig.c.read('/etc/ansible/hosts')
    InventoryConfig.verify_required_sections_exist()
    InventoryConfig.populate_from_ansible_inventory()
    ClusterGroups.setup()

    if args.generate_initial_inventory:
        InventoryConfig.cleanup = False
        generate_inital_inventory_nodes()

    elif args.scale_in_progress:
        InventoryConfig.scale = True
        scale_inventory_groups()
    log.info("////////// End Script Invocation //////////")
