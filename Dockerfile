FROM python:3.7-slim-stretch

# set the workdir to src
WORKDIR /functions


# install cloud custodian
RUN set -ex; \
    apt-get --yes update; \
    apt-get --yes install --no-install-recommends \
    bash \
    zip; \
    apt-get purge --yes --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
    rm -rf /var/cache/apt/; \
    rm -rf /var/lib/apt/lists/*; \
    rm -rf /src/; \
    rm -rf /root/.cache/

# add the policies
COPY functions/ /functions/

RUN set -ex; \
    for folder in `ls /functions/source/` ; do \
      if [ ! -d /functions/packages/$folder ]; then \
        mkdir /functions/packages/$folder ; \
      fi ;\
      cd /functions/source/$folder;  \
      if [ -f requirements.txt ]; then \
        pip3 install -r requirements.txt -t . ; \
      fi ;\
      zip -r ../../packages/$folder/lambda.zip *; \
    done

# set the entrypoint
ENTRYPOINT ["/bin/bash"]
