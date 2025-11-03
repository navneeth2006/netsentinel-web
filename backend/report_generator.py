from jinja2 import Template
import os
from datetime import datetime

HTML_TEMPLATE = """
<html>
<head><meta charset="utf-8"><title>NetSentinel Report</title>
<style>body{font-family:Arial;background:#0b1220;color:#fff;padding:20px}h1{color:#6ee7b7}</style>
</head>
<body>
<h1>NetSentinel Scan Report - {{ target }}</h1>
<p>Run at: {{ when }}</p>

<h2>Live Hosts</h2>
<ul>
{% for h in hosts %}
  <li>{{ h }}</li>
{% endfor %}
</ul>

<h2>Open Ports</h2>
<ul>
{% for host, ports in ports.items() %}
  <li><strong>{{ host }}</strong>
    <ul>
    {% for p, open_ in ports.items() %}
      <li>Port {{ p }} — {{ 'open' if open_ else 'closed' }}</li>
    {% endfor %}
    </ul>
  </li>
{% endfor %}
</ul>

<h2>Service Banners</h2>
<pre>{{ banners }}</pre>

</body>
</html>
"""

def generate_html_report(target, hosts, ports_map, banners_text, outpath="netsentinel_report.html"):
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(target=target, when=datetime.utcnow().isoformat(), hosts=hosts, ports=ports_map, banners=banners_text)
    os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    return outpath
