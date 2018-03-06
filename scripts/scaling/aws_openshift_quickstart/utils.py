import boto3
import requests
import ConfigParser
import copy
import re
import datetime
import dateutil
import json
import os
import operator
from aws_openshift_quickstart.logger import LogUtil

class EqualsSpaceRemover:
    """
    Class to remove spaces around equal signs to confirm to INI style formatting.
    Methods:
        write: Writes the modified file to disk.
    """

    output_file = None
    def __init__( self, new_output_file ):
        self.output_file = new_output_file

    def write( self, what ):
        self.output_file.write( what.replace( " = ", "=",))

class InventoryConfig(object):
    """
    Class to hold all of the configuration related objects / methods
    Methods:
        - setup: Initial class setup.
        - populate_from_ansible_inventory: Populates the known_instances dict w/data from the ansible inventory.
        - _determine_region_name: Determines the region that the cluster is in.
        -
    """
    log = LogUtil.get_root_logger()
    region_name = None
    instance_id = None
    scale = False
    all_instances = {}
    known_instances = {}
    known_instances_iplist = []
    _instance_pattern = 'i-[0-9a-z]+'
    generate_initial_inventory = False
    inventory_file = '/etc/ansible/hosts'
    ansible_playbook_wrapper="/usr/share/ansible/openshift-ansible/scaleup_wrapper.yml"
    inventory_categories = {
                "master": [ "masters", "new_masters" ],
                "etcd": [ "etcd", "new_etcd" ],
                "node": [ "nodes", "new_nodes" ],
                "provision": [ "provision_in_progress" ]
            }
    _inventory_node_skel = {
                "master": [],
                "etcd": [],
                "node": [],
                "provision": []
            }
    _asg_node_skel = {
        "masters": [],
        "etcd": [],
        "nodes": [],
        "provision": []
    }
    provisioning_hostdefs = {}
    inventory_nodes = copy.deepcopy(_inventory_node_skel)
    inventory_nodes['ids'] = {}
    logical_names = {
                "OpenShiftEtcdASG": "etcd",
                "OpenShiftMasterASG": "masters",
                "OpenShiftNodeASG": "nodes"
            }

    @classmethod
    def setup(cls):
        """
        function to setup the variables initially (populate from inventory, etc)
        """
        cls.log.info("Setting up the InventoryConfig Class")
        cls.region_name = cls._determine_region_name()
        cls.instance_id = cls._determine_local_instance_id()
        cls.ec2 = boto3.client('ec2', cls.region_name)
        for tag in cls._grab_local_tags():
            cls.log.debug("Applying: [{}] / Value [{}] - as a method within the cluster.".format(tag['key'], tag['value']))
            setattr(cls, tag['key'], tag['value'])
        for instance in cls._grab_all_instances():
            iid = instance['InstanceId']
            cls.all_instances[iid] = instance
        cls.log.debug("The EC2 API Told me about these instances: {}".format(cls.all_instances.keys()))
        cls.log.info("InventoryConfig setup complete!")

    @classmethod
    def verify_required_sections_exist(cls):
        """
        Verifies that the required sections exist within the Inventory.
        Ex: new_(masters|nodes|etcd)
        """
        inventory_config = InventoryConfig.c
        a = cls.inventory_categories
        for x in a:
            for y in a[x]:
                if not inventory_config.has_section(y):
                    inventory_config.add_section(y)
                    if 'provision' not in y:
                        inventory_config.set('OSEv3:children', y)
    @classmethod
    def populate_from_ansible_inventory(cls):
        """
        Populates the InventoryConfig class with data from the existing anisble inventory
        """
        cls.log.info("We're populating the runtime config from data within the Ansible Inventory")
        inventory_config = InventoryConfig.c
        for category in cls.inventory_categories.keys():
            cls.log.debug("Category: {}".format(category))
            if category == 'provision':
                continue
            for subcategory in cls.inventory_categories[category]:
                cls.log.debug("\tSubcategory: {}".format(subcategory))
                for key in inventory_config.options(subcategory):
                    ip = key.split()[0]
                    cls.inventory_nodes[category].append(ip)
                    cls.log.debug("I just added {} to the {} category".format(ip, category))
                    _pattern = re.compile(cls._instance_pattern)
                    _host_kv = inventory_config.get(subcategory, key)
                    if _host_kv == None:
                        _search_string = key
                    else:
                        _search_string = _host_kv
                    _instance_id = _pattern.search(_search_string).group()
                    if _instance_id:
                        cls.known_instances[_instance_id] = ip
                        cls.known_instances_iplist.append(ip)
                        cls.log.debug("The Instance ID {} has been tied to the Private DNS Entry: {}".format(_instance_id, ip))
                    else:
                        cls.log.debug("No instance ID was found!")

    @classmethod
    def _determine_region_name(cls):
        """
        Queryies the metadata service to determine the current Availability Zone.
        Extrapolates the region based on the AZ returned
        """
        resp = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone')
        return resp.text[:-1]

    @classmethod
    def _determine_local_instance_id(cls):
        """
        Queries the metadata service to determine the local instance ID
        """
        resp = requests.get('http://169.254.169.254/latest/meta-data/instance-id')
        return resp.text

    @classmethod
    def _grab_all_instances(cls):
        """
        Generator around an ec2.describe_instances() call.
        Uses a filter to narrow down results.
        """
        filters = [{"Name":"tag:aws:cloudformation:stack-id","Values":[InventoryConfig.stack_id]}]
        all_instances = cls.ec2.describe_instances(Filters=filters)['Reservations']

        i=0
        while i < len(all_instances):
            j=0
            while j < len(all_instances[i]['Instances']):
                yield all_instances[i]['Instances'][j]
                j+=1
            i+=1

    @classmethod
    def _grab_local_tags(cls):
        """
        Grabs the Cloudformation-set tags on the local instance.
        Dependent on the results of _determine_local_instance_id()
        """
        ec2 = boto3.resource('ec2', cls.region_name)
        local_instance = ec2.Instance(cls.instance_id)
        i=0
        while i < len(local_instance.tags):
            if 'cloudformation' in local_instance.tags[i]['Key']:
                _k = local_instance.tags[i]['Key'].split(':')[2]
                yield {'key': _k.replace('-','_'), 'value': local_instance.tags[i]['Value']}
            i+=1

class InventoryScaling(object):
    """
    Class to faciliate scaling activities in the Cluster's Auto Scaling Groups.
    """
    log = LogUtil.get_root_logger()
    _incoming_instances = copy.deepcopy(InventoryConfig._inventory_node_skel)
    nodes_to_add = copy.deepcopy(InventoryConfig._asg_node_skel)
    nodes_to_remove = copy.deepcopy(InventoryConfig._asg_node_skel)

    nodes_to_add['combined'] = []
    nodes_to_remove['combined'] = []
    ansible_results = {}
    @classmethod
    def wait_for_api(cls, instance_id_list=[]):
        """
        Wait for instances in (class).nodes_to_add to show up in DescribeInstances API Calls. From there, we add them to the InventoryConfig.all_instances dictionary. This is necessary to allow the instances to be written to the Inventory config file
        """
        if not instance_id_list:
          instance_id_list = cls.nodes_to_add['combined']

        cls.log.info("[wait_for_api]: Waiting for the EC2 API to return new instances.")
        cls._client = boto3.client('ec2', InventoryConfig.region_name)
        waiter = cls._client.get_waiter('instance_exists')
        waiter.wait(InstanceIds=cls.nodes_to_add['combined'])

        for instance in cls._fetch_newly_launched_instances_from_api(cls.nodes_to_add['combined']):
            cls.log.debug("[{}] has been detected in the API.".format(instance))
            InventoryConfig.all_instances[instance['InstanceId']] = instance
        cls.log.info("[wait_for_api] Complete")

    @classmethod
    def _fetch_newly_launched_instances_from_api(cls, instance_id_list):
        """
        Generator.
        Fetches the newly-launched instances from the API.
        """
        all_instances = cls._client.describe_instances(InstanceIds=instance_id_list)['Reservations']
        i=0
        while i < len(all_instances):
            j=0
            while j < len(all_instances[i]['Instances']):
                yield all_instances[i]['Instances'][j]
                j+=1
            i+=1

    @classmethod
    def process_pipeline(cls):
        """
        ClassMethod that
            - prunes the config, removing nodes that are terminating.
            - adds nodes to the config that just launched
        """
        cls.log.info("We're processing the scaling pipeline")
        # Remove the nodes (from config) that are terminating.
        if cls.nodes_to_remove['combined']:
            cls.log.info("We have the following nodes to remove from the inventory:")
            cls.log.info("{}".format(cls.nodes_to_remove['combined']))
            for category in cls.nodes_to_remove.keys():
                if category == 'combined':
                    continue
                cls.remove_node_from_section(cls.nodes_to_remove[category], category)
        else:
          cls.log.info("No nodes were found to remove from the inventory.")

        # Add the nodes that are launching.
        if cls.nodes_to_add['combined']:
            cls.log.info("We have the following nodes to add to the inventory:")
            cls.log.info("{}".format([x.split()[0] for x in cls.nodes_to_add['combined']]))
            for category in cls.nodes_to_add.keys():
                if category == 'combined':
                    continue
                cls._incoming_instances[category] = [x.split()[0] for x in cls.nodes_to_add[category]]
                cls.log.debug("Adding nodes {} to the {} category".format(cls._incoming_instances[category], category))
                cls.add_nodes_to_section(cls.nodes_to_add[category], category)
            cls.log.info("Complete!")
        else:
          cls.log.info("No nodes were found to add to the inventory.")

    @classmethod
    def add_nodes_to_section(cls, node_list, category, fluff=True, migrate=False):
        """
        Adds a node (private IP) to a config section
        """
        c = InventoryConfig.c
        if not migrate:
            _provisioning_section = InventoryConfig.inventory_categories['provision'][0]
            if not c.has_section(_provisioning_section):
                c.set('OSEv3:children', _provisioning_section)
            if not c.has_section('new_'+category):
                if category == 'provision':
                    pass
                else:
                    c.set('OSEv3:children', 'new_'+category)

            for n in node_list:
                ip = n.split()[0]
                if ip in InventoryConfig.known_instances_iplist:
                    continue
                if fluff:
                    _new_node_section='new_'+category
                else:
                    _new_node_section = category

                if not c.has_option(_provisioning_section, ip):
                    c.set(_provisioning_section, ip)
                if not c.has_option(_new_node_section, n):
                    c.set(_new_node_section, n)
        else:
            for n in node_list:
                c.set(category, n)


    @classmethod
    def remove_node_from_section(cls, node, category, migrate=False):
        """
        ClassMethod to remove a list of nodes from a list of categories within the config file. .
        """
        c = InventoryConfig.c
        migration_removed = []
        categories = [ category, '{}_{}'.format('new',category)]
        if migrate:
            del categories[categories.index(category)]
        categories += InventoryConfig.inventory_categories['provision']
        for cat in categories:
            for n in node:
              if 'provision' in cat:
                c.remove_option(cat, n)
                continue
              for idx in c.options(cat):
                  if idx.split()[0] == n:
                      if migrate:
                          full_idx = c.get(cat, idx)
                          if full_idx is None:
                            full_idx = idx
                          migration_removed.append(full_idx)
                      c.remove_option(cat, idx)
                      continue
        if migrate:
            return migration_removed


    @classmethod
    def migrate_nodes_between_section(cls, node, category):
        """
        Wrapper to migrate successful nodes between new_{category} and {category}
        labels within the Ansible inventory. Additionally removes node from the
        provisioning category.
        """
        addlist = cls.remove_node_from_section(node, category, migrate=True)
        if 'master' in category:
          _ = cls.remove_node_from_section(node, 'nodes', migrate=True)
        cls.add_nodes_to_section(addlist, category, migrate=True)
        cls.log.info("Nodes: {} have been permanately added to the Inventory under the {} category".format(node, category))
        cls.log.info("They've additionally been removed from the provision_in_progress category")

    @classmethod
    def process_playbook_json_output(cls, jout_file, category):
        """
        Processes the output from the ansible playbook run and
        determines what hosts failed / were unreachable / succeeded.

        The results are put in (Class).ansible_results, keyed by category name.
        """
        # The json_end_idx reference below is important. The playbook run is in json output,
        # however the text we're opening here is a mix of free-text and json.
        # it's formatted like this.
        #   <optional> free text
        #   Giant Glob of JSON
        #   <optional> free text.
        # The json_end_idx variable in this function defines the end of the json.
        # Without it, JSON parsing will fail.
        dt = datetime.datetime.now()
        with open(jout_file, 'r') as f:
            all_output = f.readlines()
        if len(all_output) > 1:
            json_start_idx = all_output.index('{\n')
            json_end_idx, _ = max(enumerate(all_output), key=operator.itemgetter(1))
        else:
            idx = 0

        j = json.loads(''.join(all_output[json_start_idx:json_end_idx+1]))['stats']
        unreachable = []
        failed = []
        succeeded = []
        del j['localhost']
        for h in j.keys():
            if j[h]['unreachable'] != 0:
                unreachable.append(h)
            elif j[h]['failures'] !=0:
                failed.append(h)
            else:
                succeeded.append(h)
        # Pruning down to category only.
        cat_results = {
                'succeeded': [x for x in succeeded if x in cls._incoming_instances[category]],
                'failed': [x for x in failed if x in cls._incoming_instances[category]],
                'unreachable': [x for x in unreachable if x in cls._incoming_instances[category]]
            }
        cls.ansible_results[category] = cat_results
        cls.log.info("- [{}] playbook run results: {}".format(category, cat_results))
        final_logfile = "/var/log/aws-quickstart-openshift-scaling.{}-{}-{}T{}{}".format(dt.year, dt.month, dt.day, dt.hour, dt.minute)
        os.rename(jout_file, final_logfile)
        cls.log.info("The json output logfile has been moved to %s" %(final_logfile))

class LocalScalingActivity(object):
    """
    Class to objectify each scaling activity within an ASG
    """
    def __init__(self, json_doc):
        self._json = json_doc
        self.start_time = self._json['StartTime']
        self._instance_pattern = 'i-[0-9a-z]+'
        self.type = self._determine_scale_type()
        if self.type:
            self.instance = self._determine_affected_instance()
        del self._json

    def _determine_affected_instance(self):
        """
        Determines the affected instance for the scaling event.
        """
        _pattern = re.compile(self._instance_pattern)
        _instance_id = _pattern.search(self._json['Description'])
        if _instance_id:
            return _instance_id.group()
        else:
            return None

    def _determine_scale_type(self):
        """
        Determines the scaling event type (scale in, or scale out)
        """
        if self._json['StatusCode'] == 'Failed':
            return False
        _t = self._json['Description'].split()[0]
        if 'Launching' in _t:
            _type = "launch"
        elif 'Terminating' in _t:
            _type = "terminate"
        else:
            _type = None
        return _type

class LocalASG(object):
    """
    Class to objectify an ASG
    """
    def __init__(self, json_doc, required_stack_id=None):
        self.log = LogUtil.get_root_logger()
        self._instances = {'list':[], "scaling":[]}
        self._asg = boto3.client('autoscaling', InventoryConfig.region_name)
        self.name = json_doc['AutoScalingGroupName']
        self.private_ips = []
        self.node_hostdefs = []
        self.scale_override = True
        self.scaling_events = []
        self.scale_in_progress_instances = {'terminate':[], 'launch':[]}
        self.cooldown = json_doc['DefaultCooldown']
        self.logical_name = None
        self._cooldown_upperlimit = self.cooldown * 3
        if self._cooldown_upperlimit >= 300:
          self._cooldown_upperlimit = 300
        self.elb_name = None
        self.stack_id = None
        for tag in self._grab_tags(json_doc['Tags']):
            self.__dict__[tag['key']] = tag['value']
        self.in_openshift_cluster = self._determine_cluster_membership()
        if self.in_openshift_cluster:
            # Set the logcal_name
            self.logical_name = InventoryConfig.logical_names[self.logical_id]
            # Sanity check to verify they're in the API.
            # - and populate the InventoryConfig.all_instances dict as a result.
            # - working around edge cases.
            ilist = [i['InstanceId'] for i in json_doc['Instances']]
            InventoryScaling.wait_for_api(instance_id_list=ilist)
            # Grab instances
            for instance in self._grab_instance_metadata(json_doc['Instances']):
                self._instances[instance.InstanceId] = instance
                self._instances['list'].append(instance.InstanceId)
                self.private_ips += instance.private_ips
            # Grab scaling events. Anything newer than (self.cooldown * 3).
            # However, only do so if we're not populating the initial inventory.
            if not InventoryConfig.generate_initial_inventory:
                for scaling_event in self._grab_current_scaling_events():
                    self.scaling_events.append(scaling_event)
                    # If the instance is not already in the config. Done to compensate for the self._cooldown_upperlimit var.
                    if (scaling_event.type == 'launch') and (scaling_event.instance in InventoryConfig.known_instances.keys()):
                        continue
                    if (scaling_event.type == 'launch') and (scaling_event.instance in self.scale_in_progress_instances['terminate']):
                        continue
                    self.scale_in_progress_instances[scaling_event.type].append(scaling_event.instance)
                    self._instances['scaling'].append(scaling_event.instance)
                for instance in self._instances['list']:
                  if (instance not in InventoryConfig.known_instances.keys()) and (instance not in self._instances['scaling']):
                    self.scale_in_progress_instances['launch'].append(instance)
                    self.scale_override = True
            self.openshift_config_category = self._determine_openshift_category(self.logical_id)
            # Grab Inventory host definitions
            for combined_hostdef in self.generate_asg_node_hostdefs():
                instance_id, hostdef = combined_hostdef
                self.node_hostdefs.append(hostdef)
                InventoryConfig.provisioning_hostdefs[instance_id] = hostdef

    def _grab_tags(self, tag_json):
        """
        Descriptor to grabs the tags for an ASG
        """
        i=0
        while i < len(tag_json):
            if 'cloudformation' in tag_json[i]['Key']:
                _k = tag_json[i]['Key'].split(':')[2]
                yield {'key': _k.lower().replace('-','_'), 'value': tag_json[i]['Value']}
            i+=1

    def _determine_cluster_membership(self):
        """
        Determines if the ASG is within the OpenShift Cluster
        """
        if self.stack_id == InventoryConfig.stack_id:
          self.log.debug("{} matches {} for ASG: {}".format(self.stack_id, InventoryConfig.stack_id, self.name))
          self.log.info("Awesome! This ASG is in the openshift cluster:" + self.name)
          return True
        self.log.debug("{} != {} for ASG: {}".format(self.stack_id, InventoryConfig.stack_id, self.name))
        self.log.info("This ASG is not in the openshift cluster")
        return False

    def _grab_current_scaling_events(self):
        """
        Descriptor to query the EC2 API to fetch the current scaling events for the ASG.
        """
        _now = datetime.datetime.now().replace(tzinfo=dateutil.tz.tzlocal())
        scaling_activities = self._asg.describe_scaling_activities(AutoScalingGroupName=self.name)['Activities']
        i=0
        while i < len(scaling_activities):
            _se = LocalScalingActivity(scaling_activities[i])
            i+=1
            # If the scaling activity was not successful, move along.
            if not _se.type:
                continue
            _diff = _now - _se.start_time
            if _diff.days == 0 and (_diff.seconds <= self._cooldown_upperlimit):
                yield _se

    def _grab_instance_metadata(self, json_doc):
        """
        Generator to grab the metadata of the ansible controller (local) instance.
        """
        i=0
        while i < len(json_doc):
            yield LocalASInstance(json_doc[i]['InstanceId'])
            i+=1

    def _determine_openshift_category(self, logical_id):
        """
        Determine the openshift category (etcd/nodes/master)
        """
        try:
            openshift_category = InventoryConfig.logical_names[logical_id]
        except KeyError:
            return None
        return openshift_category

    def generate_asg_node_hostdefs(self):
        """
        Generates the host definition for populating the Ansible Inventory.
        """
        i = 0
        while i < len(self._instances['list']):
            instance_id = self._instances['list'][i]
            node = self._instances[instance_id]
            # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceState.html
            if node.State['Code'] not in [0, 16]:
                i+=1
                continue
            _1 = node.PrivateDnsName
            _2 = ''
            _3 = ''
            _4 = "openshift_node_labels=\"{'application_node': 'yes', 'registry_node': 'yes', 'router_node': 'yes', 'region': 'infra', 'zone': 'default'} \""
            _5 = ''
            _6 = '# '+ instance_id

            if 'master' in self.openshift_config_category:
                if self.elb_name:
                    # openshift_public_hostname is only needed if we're dealing with masters, and an ELB is present.
                    _3 = "openshift_public_hostname=" + self.elb_name
                # (#5) is only needed if we're dealing with master nodes.
                _5 = "openshift_schedulable=false"
                # Labeling the master nodes differently
                _4 = "openshift_node_labels=\"{'region': 'primary', 'zone': 'default'} \""

            elif not 'node' in self.openshift_config_category:
                # Nodes don't need openshift_public_hostname (#3), or openshift_schedulable (#5)
                # etcd only needs hostname and node labes. doing the 'if not' above addresses both
                # of these conditions at once, as the remainder are default values prev. defined.
                _4 = ''

            hostdef = "{} {} {} {} {} {}".format(_1.ljust(15), _2.ljust(25), _3, _4, _5, _6)
            i+=1
            yield (instance_id, hostdef)

class LocalASInstance(object):
    """
    Class around each instance within an ASG
    """
    def __init__(self, instance_id):
        self.private_ips = []
        try:
            instance_object = InventoryConfig.all_instances[instance_id]
            for ip in self._extract_private_ips(instance_object['NetworkInterfaces']):
                self.private_ips.append(ip)
            self.__dict__.update(**instance_object)
        except KeyError:
            pass

    def _extract_private_ips(self, network_json):
        """
        Generator that extracts the private IPs from the instance.
        """
        i=0
        while i < len(network_json):
            yield network_json[i]['PrivateDnsName']
            i+=1

class ClusterGroups(object):
    """
    Class around the ASGs within the Cluster
    """
    groups = []
    @classmethod
    def setup(cls):
        for group in cls._determine_cluster_groups():
            cls.groups.append(group)

    # TODO: Should be depreciated.
    @classmethod
    def fetch_groups(cls):
        return cls.groups

    @classmethod
    def _determine_cluster_groups(cls):
        """
        Generator that determines what ASGs are within the cluster.
        """
        asg = boto3.client('autoscaling', InventoryConfig.region_name)
        all_groups = asg.describe_auto_scaling_groups()['AutoScalingGroups']
        i=0
        while i < len(all_groups):
            _g = LocalASG(all_groups[i])
            i+=1
            if _g.in_openshift_cluster:
                yield _g
