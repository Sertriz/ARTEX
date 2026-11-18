// Verified alias table. Change it only with evidence from a real NVD record.

package cvematch

// aliasData maps what scanners report to the vendor:product pairs NVD actually
// files CVEs under. Every pair was verified against real NVD CVE API 2.0 records
// (one evidence CVE is noted per pair) by an independent research-then-verify
// pass: a researcher fetched real records for each product, a second verifier
// re-fetched them and refuted what did not hold. Names that denote another
// product, a module or an ambiguous family (a bare "Apache", "LiteSpeed",
// "MiniServ", "WebLogic") were rejected. See docs/cve-correlation-design.md.
var aliasData = []aliasTable{
	// Apache HTTP Server: apache:http_server (CVE-2021-41773)
	{pairs: pp("apache:http_server"), names: []string{"Apache Advanced Extranet Server httpd", "Apache HTTP Server", "Apache httpd", "Net Integration Modified Apache httpd"}},
	// nginx: f5:nginx (CVE-2009-3896), f5:nginx_open_source (CVE-2024-7347), nginx:nginx (CVE-2009-3896)
	{pairs: pp("f5:nginx", "f5:nginx_open_source", "nginx:nginx"), stale: pp("igor_sysoev:nginx"), names: []string{"Nginx", "nginx"}},
	// Microsoft IIS: microsoft:internet_information_services (CVE-2000-0884), microsoft:internet_information_server (CVE-2000-0884)
	{pairs: pp("microsoft:internet_information_services", "microsoft:internet_information_server"), stale: pp("microsoft:iis"), names: []string{"IIS", "IIS ftpd", "Microsoft IIS ftpd", "Microsoft IIS httpd", "Microsoft IIS SSL", "Microsoft IIS WebDAV", "Microsoft-IIS"}},
	// LiteSpeed Web Server: litespeedtech:litespeed_web_server (CVE-2010-2333), litespeed_technologies:litespeed_web_server (CVE-2005-3695)
	{pairs: pp("litespeedtech:litespeed_web_server", "litespeed_technologies:litespeed_web_server")},
	// OpenResty: openresty:openresty (CVE-2018-9230)
	{pairs: pp("openresty:openresty"), stale: pp("openresty:ngx_openresty"), names: []string{"ngx_openresty", "openresty", "OpenResty", "OpenResty web app server"}},
	// lighttpd: lighttpd:lighttpd (CVE-2008-4359)
	{pairs: pp("lighttpd:lighttpd"), names: []string{"lighttpd"}},
	// Caddy: caddyserver:caddy (CVE-2018-19148)
	{pairs: pp("caddyserver:caddy"), stale: pp("matt_holt:caddy"), names: []string{"Caddy", "Caddy httpd"}},
	// Apache Tomcat: apache:tomcat (CVE-2002-0682)
	{pairs: pp("apache:tomcat"), names: []string{"Apache Tomcat", "Apache Tomcat httpd"}},
	// Jetty: eclipse:jetty (CVE-2017-7657), mortbay:jetty (CVE-2009-1523), mortbay_jetty:jetty (CVE-2007-5615), jetty:jetty (CVE-2006-2758), jetty:jetty_http_server (CVE-2004-2478)
	{pairs: pp("eclipse:jetty", "mortbay:jetty", "mortbay_jetty:jetty", "jetty:jetty", "jetty:jetty_http_server"), names: []string{"Jetty"}},
	// HAProxy: haproxy:haproxy (CVE-2013-1912)
	{pairs: pp("haproxy:haproxy"), names: []string{"HAProxy", "HAProxy http proxy", "HAProxy stats socket"}},
	// Squid: squid-cache:squid (CVE-2014-3609), squid:squid (CVE-2009-0478)
	{pairs: pp("squid-cache:squid", "squid:squid"), names: []string{"squid", "Squid", "Squid ftp proxy", "Squid http proxy"}},
	// Varnish: varnish_cache_project:varnish_cache (CVE-2013-4484), varnish-cache:varnish (CVE-2013-4484), varnish-software:varnish_cache (CVE-2017-12425), varnish-cache:varnish_cache (CVE-2020-11653), varnish-software:varnich_cache (CVE-2022-23959)
	{pairs: pp("varnish_cache_project:varnish_cache", "varnish-cache:varnish", "varnish-software:varnish_cache", "varnish-cache:varnish_cache", "varnish-software:varnich_cache"), names: []string{"Varnish", "Varnish Cache CLI", "Varnish http accelerator"}},
	// Traefik: traefik:traefik (CVE-2018-15598), containous:traefik (CVE-2021-27375)
	{pairs: pp("traefik:traefik", "containous:traefik"), names: []string{"Traefik"}},
	// Envoy: envoyproxy:envoy (CVE-2019-9900)
	{pairs: pp("envoyproxy:envoy"), names: []string{"envoy", "Envoy"}},
	// Tinyproxy: tinyproxy_project:tinyproxy (CVE-2017-11747), banu:tinyproxy (CVE-2011-1499)
	{pairs: pp("tinyproxy_project:tinyproxy", "banu:tinyproxy"), names: []string{"tinyproxy", "tinyproxy http proxy"}},
	// Gunicorn: gunicorn:gunicorn (CVE-2018-1000164)
	{pairs: pp("gunicorn:gunicorn"), names: []string{"Gunicorn", "gunicorn"}},
	// uWSGI: unbit:uwsgi (CVE-2018-6758)
	{pairs: pp("unbit:uwsgi"), names: []string{"uWSGI"}},
	// Werkzeug: palletsprojects:werkzeug (CVE-2016-10516)
	{pairs: pp("palletsprojects:werkzeug"), stale: pp("pocoo:werkzeug"), names: []string{"Werkzeug", "Werkzeug httpd"}},
	// Node.js: nodejs:node.js (CVE-2015-5380), nodejs:nodejs (CVE-2013-4450)
	{pairs: pp("nodejs:node.js", "nodejs:nodejs"), names: []string{"node.js", "Node.js", "Node.js httpd"}},
	// Express: openjsf:express (CVE-2014-6393)
	{pairs: pp("openjsf:express"), stale: pp("expressjs:express"), names: []string{"Express", "Express.js httpd", "Node.js Express framework"}},
	// OpenSSH: openbsd:openssh (CVE-2006-5051)
	{pairs: pp("openbsd:openssh"), names: []string{"libwrap'd OpenSSH", "OpenSSH"}},
	// Dropbear SSH: dropbear_ssh_project:dropbear_ssh (CVE-2004-2486)
	{pairs: pp("dropbear_ssh_project:dropbear_ssh"), stale: pp("matt_johnston:dropbear_ssh_server"), names: []string{"Dropbear sshd"}},
	// Erlang/OTP: erlang:erlang/otp (CVE-2014-1693)
	{pairs: pp("erlang:erlang/otp"), stale: pp("erlang:otp", "erlang:erlang%2fotp"), names: []string{"Erlang", "Erlang OTP"}},
	// libssh: libssh:libssh (CVE-2014-0017)
	{pairs: pp("libssh:libssh"), names: []string{"libssh"}},
	// Exim: exim:exim (CVE-2019-10149), university_of_cambridge:exim (CVE-2005-0022)
	{pairs: pp("exim:exim", "university_of_cambridge:exim"), names: []string{"Exim smtpd"}},
	// Postfix: postfix:postfix (CVE-2023-51764), wietse_venema:postfix (CVE-2003-0540)
	{pairs: pp("postfix:postfix", "wietse_venema:postfix"), names: []string{"Postfix qmqpd", "Postfix smtpd"}},
	// Sendmail: sendmail:sendmail (CVE-2023-51765)
	{pairs: pp("sendmail:sendmail"), stale: pp("proofpoint:sendmail"), names: []string{"Sendmail", "Sendmail smtpd"}},
	// OpenSMTPD: openbsd:opensmtpd (CVE-2020-7247), opensmtpd:opensmtpd (CVE-2020-8794)
	{pairs: pp("openbsd:opensmtpd", "opensmtpd:opensmtpd")},
	// Dovecot: dovecot:dovecot (CVE-2022-30550), open-xchange:dovecot (CVE-2025-59028)
	{pairs: pp("dovecot:dovecot", "open-xchange:dovecot"), names: []string{"Dovecot DirectAdmin imapd", "Dovecot DirectAdmin pop3d", "Dovecot imapd", "Dovecot lmtpd", "Dovecot MUA imapd", "Dovecot MUA pop3d", "Dovecot pop3d"}},
	// Microsoft Exchange Server: microsoft:exchange_server (CVE-2021-26855), microsoft:exchange_server_subscription_edition (CVE-2025-53786)
	{pairs: pp("microsoft:exchange_server", "microsoft:exchange_server_subscription_edition"), names: []string{"Microsoft Exchange 2000 imapd", "Microsoft Exchange 2000 pop3d", "Microsoft Exchange 2000 Server Chat Service", "Microsoft Exchange 2003 imapd", "Microsoft Exchange 2003 pop3d", "Microsoft Exchange 2007 imapd", "Microsoft Exchange 2007 pop3d", "Microsoft Exchange 2007-2010 imapd", "Microsoft Exchange 2007-2010 pop3d", "Microsoft Exchange 2010 log copier", "Microsoft Exchange 2010 smtpd", "Microsoft Exchange Internet News Service"}},
	// Zimbra: synacor:zimbra_collaboration_suite (CVE-2022-27925), zimbra:collaboration (CVE-2024-27443), synacor:zimbra_collaboration_server (CVE-2015-2249), zimbra:collaboration_server (CVE-2019-15313)
	{pairs: pp("synacor:zimbra_collaboration_suite", "zimbra:collaboration", "synacor:zimbra_collaboration_server", "zimbra:collaboration_server")},
	// Roundcube: roundcube:webmail (CVE-2020-35730), roundcube:roundcube_webmail (CVE-2015-8770)
	{pairs: pp("roundcube:webmail", "roundcube:roundcube_webmail"), names: []string{"RoundCube"}},
	// vsftpd: vsftpd_project:vsftpd (CVE-2011-2523), beasts:vsftpd (CVE-2004-0042), redhat:vsftpd (CVE-2008-2375)
	{pairs: pp("vsftpd_project:vsftpd", "beasts:vsftpd", "redhat:vsftpd"), stale: pp("vsftpd:vsftpd"), names: []string{"vsftpd"}},
	// ProFTPD: proftpd:proftpd (CVE-2010-4221), proftpd_project:proftpd (CVE-2006-5815)
	{pairs: pp("proftpd:proftpd", "proftpd_project:proftpd"), names: []string{"ProFTPD"}},
	// Pure-FTPd: pureftpd:pure-ftpd (CVE-2011-0418), pureftpd:pureftpd (CVE-2004-0656)
	{pairs: pp("pureftpd:pure-ftpd", "pureftpd:pureftpd"), names: []string{"Pure-FTPd"}},
	// FileZilla Server: filezilla-project:filezilla_server (CVE-2005-0850), filezilla:filezilla_server (CVE-2006-2173), filezilla:filezilla_server_terminal (CVE-2005-3589)
	{pairs: pp("filezilla-project:filezilla_server", "filezilla:filezilla_server", "filezilla:filezilla_server_terminal"), names: []string{"FileZilla ftpd", "FileZilla Server admin service"}},
	// MySQL: oracle:mysql (CVE-2012-2122), oracle:mysql_server (CVE-2025-21521), mysql:mysql (CVE-2006-1516), mysql:mysql_server (CVE-2007-5969), mysql:community_server (CVE-2007-5969), mysql:mysql_community_server (CVE-2012-1696), mysql:mysql_enterprise_server (CVE-2007-5969)
	{pairs: pp("oracle:mysql", "oracle:mysql_server", "mysql:mysql", "mysql:mysql_server", "mysql:community_server", "mysql:mysql_community_server", "mysql:mysql_enterprise_server"), names: []string{"MySQL", "MySQL X protocol listener"}},
	// MariaDB: mariadb:mariadb (CVE-2012-2122)
	{pairs: pp("mariadb:mariadb"), names: []string{"MariaDB"}},
	// PostgreSQL: postgresql:postgresql (CVE-2007-6600)
	{pairs: pp("postgresql:postgresql"), names: []string{"PostgreSQL", "PostgreSQL DB"}},
	// Redis: redis:redis (CVE-2021-32626), redislabs:redis (CVE-2015-4335)
	{pairs: pp("redis:redis", "redislabs:redis"), names: []string{"Redis", "Redis key-value store"}},
	// MongoDB: mongodb:mongodb (CVE-2013-1892)
	{pairs: pp("mongodb:mongodb"), names: []string{"MongoDB", "MongoDB http console", "MongoDB simple REST interface"}},
	// Elasticsearch: elastic:elasticsearch (CVE-2014-3120), elasticsearch:elasticsearch (CVE-2014-6439)
	{pairs: pp("elastic:elasticsearch", "elasticsearch:elasticsearch"), names: []string{"Elasticsearch", "Elasticsearch binary API", "Elasticsearch REST API"}},
	// Kibana: elastic:kibana (CVE-2015-4093), elasticsearch:kibana (CVE-2017-11479)
	{pairs: pp("elastic:kibana", "elasticsearch:kibana"), names: []string{"Elasticsearch Kibana", "Kibana"}},
	// Memcached: memcached:memcached (CVE-2011-4971)
	{pairs: pp("memcached:memcached"), names: []string{"Memcached"}},
	// Apache CouchDB: apache:couchdb (CVE-2010-0009)
	{pairs: pp("apache:couchdb"), names: []string{"CouchDB"}},
	// Microsoft SQL Server: microsoft:sql_server (CVE-2002-0649), microsoft:sql_server_2000 (CVE-2012-0158), microsoft:sql_server_2005 (CVE-2012-0158), microsoft:sql_server_2008 (CVE-2012-0158), microsoft:sql_server_2016 (CVE-2024-37320), microsoft:sql_server_2017 (CVE-2024-37320), microsoft:sql_server_2019 (CVE-2024-37320), microsoft:sql_server_2022 (CVE-2024-37320), microsoft:sql_server_2025 (CVE-2026-50468)
	{pairs: pp("microsoft:sql_server", "microsoft:sql_server_2000", "microsoft:sql_server_2005", "microsoft:sql_server_2008", "microsoft:sql_server_2016", "microsoft:sql_server_2017", "microsoft:sql_server_2019", "microsoft:sql_server_2022", "microsoft:sql_server_2025"), names: []string{"Microsoft SQL Server", "Microsoft SQL Server 2000", "Microsoft SQL Server 2005", "Microsoft SQL Server 2008", "Microsoft SQL Server 2008 R2", "Microsoft SQL Server 2012", "Microsoft SQL Server 2014", "Microsoft SQL Server 2016", "Microsoft SQL Server 2017", "Microsoft SQL Server 2019", "Microsoft SQL Server 2022"}},
	// Apache Solr: apache:solr (CVE-2012-6612)
	{pairs: pp("apache:solr"), names: []string{"Apache Solr", "Solr"}},
	// RabbitMQ: pivotal_software:rabbitmq (CVE-2014-9494), vmware:rabbitmq (CVE-2021-22116), broadcom:rabbitmq_server (CVE-2014-9650)
	{pairs: pp("pivotal_software:rabbitmq", "vmware:rabbitmq", "broadcom:rabbitmq_server"), names: []string{"RabbitMQ"}},
	// Apache ActiveMQ: apache:activemq (CVE-2015-5254)
	{pairs: pp("apache:activemq"), names: []string{"ActiveMQ OpenWire transport", "Apache ActiveMQ"}},
	// Eclipse Mosquitto: eclipse:mosquitto (CVE-2017-7650)
	{pairs: pp("eclipse:mosquitto")},
	// Samba: samba:samba (CVE-2017-7494)
	{pairs: pp("samba:samba"), names: []string{"Samba nmbd netbios-ns", "Samba smbd", "Samba SWAT administration server"}},
	// ISC BIND: isc:bind (CVE-2020-8617)
	{pairs: pp("isc:bind"), names: []string{"BIND stats httpd", "Check Point Meta IP ISC BIND", "ISC BIND", "Plesk Onyx BIND"}},
	// dnsmasq: thekelleys:dnsmasq (CVE-2017-14491)
	{pairs: pp("thekelleys:dnsmasq"), names: []string{"dnsmasq"}},
	// OpenLDAP: openldap:openldap (CVE-2020-12243)
	{pairs: pp("openldap:openldap"), names: []string{"OpenLDAP", "OpenLDAP fingerd", "OpenLDAP over SSL"}},
	// CUPS: apple:cups (CVE-2017-18190), cups:cups (CVE-2015-1158), openprinting:cups (CVE-2022-26691)
	{pairs: pp("apple:cups", "cups:cups", "openprinting:cups"), names: []string{"CUPS"}},
	// Netatalk: netatalk:netatalk (CVE-2018-1160)
	{pairs: pp("netatalk:netatalk"), names: []string{"Netatalk"}},
	// OpenVPN: openvpn:openvpn (CVE-2014-8104)
	{pairs: pp("openvpn:openvpn"), names: []string{"OpenVPN", "OpenVPN Management Interface"}},
	// OpenSSL: openssl:openssl (CVE-2014-0160)
	{pairs: pp("openssl:openssl"), names: []string{"OpenSSL", "OpenSSL DTLS 1.0", "OpenSSL s_server -WWW httpd", "OpenSSL s_server -www httpd"}},
	// Asterisk: digium:asterisk (CVE-2012-5976), sangoma:asterisk (CVE-2022-37325), asterisk:asterisk (CVE-2024-42365)
	{pairs: pp("digium:asterisk", "sangoma:asterisk", "asterisk:asterisk"), names: []string{"Asterisk", "Asterisk Call Manager", "Asterisk http config", "Asterisk PBX", "Asterisk PBX httpd", "Digium Asterisk AJAM", "Digium Asterisk GUI httpd"}},
	// Webmin: webmin:webmin (CVE-2006-3392), gentoo:webmin (CVE-2012-2981)
	{pairs: pp("webmin:webmin", "gentoo:webmin"), names: []string{"Webmin"}},
	// VMware ESXi: vmware:esxi (CVE-2012-2448)
	{pairs: pp("vmware:esxi"), names: []string{"VMware ESXi"}},
	// VMware vCenter Server: vmware:vcenter_server (CVE-2015-2342)
	{pairs: pp("vmware:vcenter_server"), names: []string{"VMware vCenter Server"}},
	// Openfire: igniterealtime:openfire (CVE-2008-6508)
	{pairs: pp("igniterealtime:openfire"), names: []string{"Ignite Realtime Openfire Jabber server"}},
	// Zabbix: zabbix:zabbix (CVE-2013-5743), zabbix:frontend (CVE-2023-29454), zabbix:zabbix_server (CVE-2023-32725)
	{pairs: pp("zabbix:zabbix", "zabbix:frontend", "zabbix:zabbix_server"), names: []string{"Zabbix", "Zabbix Monitoring System"}},
	// Splunk: splunk:splunk (CVE-2012-1908)
	{pairs: pp("splunk:splunk"), stale: pp("splunk:splunk_enterprise"), names: []string{"Splunkd httpd"}},
	// Grafana: grafana:grafana (CVE-2018-15727)
	{pairs: pp("grafana:grafana"), names: []string{"Grafana http"}},
	// Jenkins: jenkins:jenkins (CVE-2016-0792)
	{pairs: pp("jenkins:jenkins"), names: []string{"Jenkins", "Jenkins httpd"}},
	// GitLab: gitlab:gitlab (CVE-2016-4340)
	{pairs: pp("gitlab:gitlab"), names: []string{"GitLab"}},
	// Gitea: gitea:gitea (CVE-2018-18926)
	{pairs: pp("gitea:gitea"), names: []string{"Gitea"}},
	// HashiCorp Consul: hashicorp:consul (CVE-2018-19653)
	{pairs: pp("hashicorp:consul"), names: []string{"HashiCorp Consul agent", "HashiCorp Consul RPC", "HashiCorp Consul service discovery httpd"}},
	// HashiCorp Vault: hashicorp:vault (CVE-2020-16250)
	{pairs: pp("hashicorp:vault"), names: []string{"Hashicorp Vault"}},
	// MinIO: minio:minio (CVE-2020-11012)
	{pairs: pp("minio:minio"), names: []string{"MinIO", "MinIO S3-compatible object store"}},
	// Nextcloud: nextcloud:nextcloud_server (CVE-2016-9459)
	{pairs: pp("nextcloud:nextcloud_server")},
	// phpMyAdmin: phpmyadmin:phpmyadmin (CVE-2009-1151)
	{pairs: pp("phpmyadmin:phpmyadmin"), names: []string{"phpMyAdmin"}},
	// PHP: php:php (CVE-2007-1001)
	{pairs: pp("php:php"), names: []string{"PHP", "PHP built-in httpd", "PHP cli server"}},
	// WordPress: wordpress:wordpress (CVE-2008-4769)
	{pairs: pp("wordpress:wordpress"), names: []string{"WordPress"}},
	// Drupal: drupal:drupal (CVE-2014-3704)
	{pairs: pp("drupal:drupal"), names: []string{"Drupal"}},
	// Joomla: joomla:joomla! (CVE-2015-8562)
	{pairs: pp("joomla:joomla!")},
	// jQuery: jquery:jquery (CVE-2011-4969)
	{pairs: pp("jquery:jquery"), names: []string{"jQuery"}},
	// Apache Struts: apache:struts (CVE-2010-1870)
	{pairs: pp("apache:struts")},
	// Oracle WebLogic Server: oracle:weblogic_server (CVE-2017-10271), bea:weblogic_server (CVE-2007-0422), bea_systems:weblogic_server (CVE-2008-3257)
	{pairs: pp("oracle:weblogic_server", "bea:weblogic_server", "bea_systems:weblogic_server"), names: []string{"Oracle WebLogic admin httpd", "Oracle WebLogic Server", "Oracle WebLogic Server Node Manager", "WebLogic applications server", "WebLogic httpd", "WebLogic Node Manager", "WebLogic Server", "WebLogic Server IIOP"}},
	// Atlassian Confluence: atlassian:confluence_server (CVE-2017-7415), atlassian:confluence_data_center (CVE-2021-26084), atlassian:confluence (CVE-2015-8399)
	{pairs: pp("atlassian:confluence_server", "atlassian:confluence_data_center", "atlassian:confluence"), names: []string{"Atlassian Confluence", "Confluence"}},
	// Atlassian Jira: atlassian:jira_server (CVE-2019-11581), atlassian:jira_data_center (CVE-2020-14179), atlassian:jira (CVE-2018-20824)
	{pairs: pp("atlassian:jira_server", "atlassian:jira_data_center", "atlassian:jira"), names: []string{"Atlassian JIRA", "Atlassian Jira"}},
	// Liferay Portal: liferay:liferay_portal (CVE-2011-1503)
	{pairs: pp("liferay:liferay_portal"), names: []string{"Liferay", "Liferay Portal"}},
	// Magento / Adobe Commerce: magento:magento (CVE-2015-1397), adobe:magento (CVE-2022-24086), adobe:commerce (CVE-2022-24086)
	{pairs: pp("magento:magento", "adobe:magento", "adobe:commerce"), names: []string{"Adobe Commerce", "Magento", "Magento Open Source"}},
	// Moodle: moodle:moodle (CVE-2008-5153)
	{pairs: pp("moodle:moodle"), names: []string{"Moodle"}},
	// MediaWiki: mediawiki:mediawiki (CVE-2008-5249)
	{pairs: pp("mediawiki:mediawiki"), names: []string{"MediaWiki"}},
	// Django: djangoproject:django (CVE-2008-3909), django_project:django (CVE-2007-0404)
	{pairs: pp("djangoproject:django", "django_project:django"), names: []string{"Django"}},
	// Ruby on Rails: rubyonrails:rails (CVE-2019-5418), rubyonrails:ruby_on_rails (CVE-2013-0156)
	{pairs: pp("rubyonrails:rails", "rubyonrails:ruby_on_rails"), names: []string{"Ruby on Rails"}},
	// Laravel: laravel:framework (CVE-2021-43617), laravel:laravel (CVE-2018-15133)
	{pairs: pp("laravel:framework", "laravel:laravel"), names: []string{"Laravel"}},
	// Microsoft ASP.NET: microsoft:asp.net (CVE-2004-0847)
	{pairs: pp("microsoft:asp.net"), names: []string{"ASP.NET", "Microsoft ASP.NET"}},
	// Fortinet FortiOS: fortinet:fortios (CVE-2016-6909)
	{pairs: pp("fortinet:fortios")},
	// Citrix ADC / NetScaler: citrix:netscaler_application_delivery_controller (CVE-2018-5314), citrix:application_delivery_controller (CVE-2023-24487), citrix:application_delivery_controller_firmware (CVE-2019-19781), citrix:netscaler_application_delivery_controller_firmware (CVE-2013-6941), citrix:netscaler_gateway (CVE-2023-3519), citrix:gateway (CVE-2022-27510), citrix:gateway_firmware (CVE-2019-19781), citrix:netscaler_gateway_firmware (CVE-2015-5080)
	{pairs: pp("citrix:netscaler_application_delivery_controller", "citrix:application_delivery_controller", "citrix:application_delivery_controller_firmware", "citrix:netscaler_application_delivery_controller_firmware", "citrix:netscaler_gateway", "citrix:gateway", "citrix:gateway_firmware", "citrix:netscaler_gateway_firmware")},
	// Ivanti Connect Secure: ivanti:connect_secure (CVE-2019-11510), pulsesecure:pulse_connect_secure (CVE-2021-22908)
	{pairs: pp("ivanti:connect_secure", "pulsesecure:pulse_connect_secure"), names: []string{"Pulse Secure"}},
	// Palo Alto PAN-OS: paloaltonetworks:pan-os (CVE-2017-15944)
	{pairs: pp("paloaltonetworks:pan-os")},
	// F5 BIG-IP: f5:big-ip_local_traffic_manager (CVE-2012-1493), f5:big-ip_access_policy_manager (CVE-2020-5902), f5:big-ip_application_security_manager (CVE-2012-1493), f5:big-ip_advanced_firewall_manager (CVE-2020-5902), f5:big-ip_advanced_web_application_firewall (CVE-2020-5902), f5:big-ip_analytics (CVE-2022-1388), f5:big-ip_application_acceleration_manager (CVE-2022-1388), f5:big-ip_ddos_hybrid_defender (CVE-2020-5902), f5:big-ip_domain_name_system (CVE-2022-1388), f5:big-ip_fraud_protection_service (CVE-2022-1388), f5:big-ip_fraud_protection_services (CVE-2023-46747), f5:big-ip_global_traffic_manager (CVE-2012-1493), f5:big-ip_link_controller (CVE-2022-1388), f5:big-ip_policy_enforcement_manager (CVE-2022-1388), f5:big-ip_carrier-grade_nat (CVE-2023-46747), f5:big-ip_ssl_orchestrator (CVE-2023-46747), f5:big-ip_webaccelerator (CVE-2023-46747), f5:big-ip_websafe (CVE-2023-46747), f5:big-ip_application_visibility_and_reporting (CVE-2023-46747), f5:tmos (CVE-2012-1493), f5:big-ip_edge_gateway (CVE-2025-20029)
	{pairs: pp("f5:big-ip_local_traffic_manager", "f5:big-ip_access_policy_manager", "f5:big-ip_application_security_manager", "f5:big-ip_advanced_firewall_manager", "f5:big-ip_advanced_web_application_firewall", "f5:big-ip_analytics", "f5:big-ip_application_acceleration_manager", "f5:big-ip_ddos_hybrid_defender", "f5:big-ip_domain_name_system", "f5:big-ip_fraud_protection_service", "f5:big-ip_fraud_protection_services", "f5:big-ip_global_traffic_manager", "f5:big-ip_link_controller", "f5:big-ip_policy_enforcement_manager", "f5:big-ip_carrier-grade_nat", "f5:big-ip_ssl_orchestrator", "f5:big-ip_webaccelerator", "f5:big-ip_websafe", "f5:big-ip_application_visibility_and_reporting", "f5:tmos", "f5:big-ip_edge_gateway"), names: []string{"BigIP", "F5 BigIP"}},
}
