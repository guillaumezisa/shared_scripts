#!/bin/bash
# Install Wazuh

# Mise a jours et installation des packages nécéssaires
echo "Mise a jours des paquets nécéssaires"
sleep 2
apt update -y
apt upgrade -y
apt install curl apt-transport-https unzip wget libcap2-bin software-properties-common lsb-release gnupg2 -y
echo ""

# Installation de OpenJdk11
echo "Installation OpenJdk"
sleep 2
echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/backports.list
apt update
export JAVA_HOME=/usr/ && apt install openjdk-11-jdk -y
echo ""

# Installation de Wazuh
echo "Installation de Wazuh"
sleep 2
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update -y
apt-get install wazuh-manager -y
echo ""

# Redémarrage Wazuh
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
echo ""

# Install & configure elasticsearch
echo "Installation d'ElasticSearch"
sleep 2
apt install elasticsearch-oss opendistroforelasticsearch -y
curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/elasticsearch/7.x/elasticsearch_all_in_one.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/elasticsearch/roles/roles.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/elasticsearch/roles/roles_mapping.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/elasticsearch/roles/internal_users.yml
echo ""

# ElasticSearch Certificates 
echo "Génération de nouveaux certificats"
sleep 2
rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f
curl -so ~/wazuh-cert-tool.sh https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/tools/certificate-utility/wazuh-cert-tool.sh
curl -so ~/instances.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/tools/certificate-utility/instances_aio.yml
bash ~/wazuh-cert-tool.sh

mkdir /etc/elasticsearch/certs/
mv ~/certs/elasticsearch* /etc/elasticsearch/certs/
mv ~/certs/admin* /etc/elasticsearch/certs/
cp ~/certs/root-ca* /etc/elasticsearch/certs/

# Redmarrage ElasticSearch 
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch
echo ""

# Charger les nouveaux certificats d'ElasticSearch
/usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem
curl -XGET https://localhost:9200 -u admin:admin -k
echo ""

# Install & configure FileBeat
echo "installation de FileBeat"
sleep 2
apt install filebeat
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/filebeat/7.x/filebeat_all_in_one.yml
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.1/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module
echo ""

# Installation des certificats FileBeat
mkdir /etc/filebeat/certs
cp ~/certs/root-ca.pem /etc/filebeat/certs/
mv ~/certs/filebeat* /etc/filebeat/certs/
echo ""

# Redémarrage de FileBeat
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
filebeat test output
echo ""

# Installation de Kibana
apt-get install opendistroforelasticsearch-kibana
curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/kibana/7.x/kibana_all_in_one.yml
mkdir /usr/share/kibana/data
chown -R kibana:kibana /usr/share/kibana/data
cd /usr/share/kibana
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.1.5_7.10.2-1.zip
echo ""

# Installation des certificats Kibana
mkdir /etc/kibana/certs
cp ~/certs/root-ca.pem /etc/kibana/certs/
mv ~/certs/kibana* /etc/kibana/certs/
chown kibana:kibana /etc/kibana/certs/*
setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node

echo ""
# Redémarrage de Kibana
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana