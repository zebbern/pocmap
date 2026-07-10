"""Product name aliases and vendor-product mappings for fuzzy matching.

These mappings enable the ProductDiscoveryService to recognize common
product name variations, abbreviations, and alternate spellings when
searching for CVEs by product name.

Example::

    from pocmap.data.product_aliases import PRODUCT_ALIASES, VENDOR_PRODUCT_MAP
    # "struts" -> resolves to canonical "apache struts"
    # "log4j2" -> resolves to canonical "log4j"
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Product aliases: canonical_name -> list of known aliases
# ---------------------------------------------------------------------------

PRODUCT_ALIASES: dict[str, list[str]] = {
    "apache struts": ["struts", "apache_struts", "struts2"],
    "log4j": ["log4j2", "log4j-core", "apache_log4j", "log4shell"],
    "apache http server": ["httpd", "apache_httpd", "apache2"],
    "nginx": ["nginx_plus"],
    "openssl": ["openssl", "heartbleed"],
    "spring framework": ["spring", "spring_framework", "spring-core"],
    "wordpress": ["wp", "wordpress_cms"],
    "drupal": ["drupal_cms"],
    "joomla": ["joomla_cms"],
    "tomcat": ["apache_tomcat"],
    "kubernetes": ["k8s", "kube"],
    "docker": ["docker_engine", "docker-ce"],
    "mysql": ["mariadb", "mysql_server"],
    "postgresql": ["postgres", "pgsql"],
    "mongodb": ["mongo"],
    "redis": ["redis_server"],
    "elasticsearch": ["elastic", "es"],
    "jenkins": ["jenkins_ci"],
    "gitlab": ["gitlab_ce", "gitlab_ee"],
    "github enterprise": ["ghe"],
    "confluence": ["atlassian_confluence"],
    "jira": ["atlassian_jira"],
    "windows": ["microsoft_windows", "win32", "win64"],
    "linux kernel": ["kernel", "linux"],
    "android": ["google_android"],
    "ios": ["apple_ios"],
    "chrome": ["google_chrome", "chromium"],
    "firefox": ["mozilla_firefox"],
    "safari": ["apple_safari"],
    "edge": ["microsoft_edge"],
    "internet explorer": ["ie", "msie"],
    "adobe acrobat": ["acrobat_reader"],
    "php": ["php_lang"],
    "python": ["python_lang"],
    "ruby": ["ruby_lang"],
    "node.js": ["nodejs", "node", "npm"],
    "react": ["reactjs"],
    "angular": ["angularjs"],
    "vue": ["vuejs"],
    "django": ["django_framework"],
    "rails": ["ruby_on_rails", "ror"],
    "laravel": ["laravel_framework"],
    "express": ["expressjs"],
    "flask": ["flask_framework"],
}

# ---------------------------------------------------------------------------
# Vendor-product mapping: vendor -> list of canonical product names
# ---------------------------------------------------------------------------

VENDOR_PRODUCT_MAP: dict[str, list[str]] = {
    "apache": ["struts", "http server", "tomcat", "log4j", "commons"],
    "microsoft": ["windows", "office", "edge", "iis", "sql server"],
    "google": ["chrome", "android", "kubernetes"],
    "oracle": ["java", "mysql", "weblogic", "database"],
    "mozilla": ["firefox", "thunderbird"],
    "apple": ["ios", "macos", "safari", "icloud"],
    "atlassian": ["confluence", "jira", "bitbucket"],
    "cisco": ["ios", "asa", "webex"],
    "vmware": ["vsphere", "esxi", "workstation"],
    "citrix": ["adc", "gateway", "xen"],
    "fortinet": ["fortios", "fortigate"],
    "palo alto": ["pan-os", "globalprotect"],
    "f5": ["big-ip", "tmui"],
    "juniper": ["junos", "screenos"],
}
