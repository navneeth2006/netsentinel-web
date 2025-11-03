const scanBtn = document.getElementById("scan");
const targetInput = document.getElementById("target");
const typeSelect = document.getElementById("type");
const statusSpan = document.getElementById("status");
const resultsSec = document.getElementById("results");
const hostsDiv = document.getElementById("hosts");
const portsDiv = document.getElementById("ports");
const bannersDiv = document.getElementById("banners");
const reportLink = document.getElementById("report");

async function startScan() {
  const target = targetInput.value.trim();
  const type = typeSelect.value;
  if (!target) { alert("Enter a target"); return; }
  statusSpan.textContent = "Queueing scan...";
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({target, type})
  });
  const data = await res.json();
  const scanId = data.scan_id;
  statusSpan.textContent = "Scan started: " + scanId;
  poll(scanId);
}

async function poll(id) {
  statusSpan.textContent = "Running...";
  while (true) {
    const r = await fetch(`/api/scan/${id}`);
    const data = await r.json();
    if (data.status === "done") {
      showResults(data);
      statusSpan.textContent = "Done";
      break;
    } else if (data.status === "error") {
      statusSpan.textContent = "Error";
      alert("Scan error: " + (data.error || "unknown"));
      break;
    }
    await new Promise(res => setTimeout(res, 1500));
  }
}

function showResults(data) {
  resultsSec.classList.remove("hidden");
  const res = data.result;
  hostsDiv.innerHTML = `<h3>Hosts</h3><pre>${JSON.stringify(res.hosts || res.host_ip || [], null, 2)}</pre>`;
  portsDiv.innerHTML = `<h3>Ports</h3><pre>${JSON.stringify(res.ports, null, 2)}</pre>`;
  bannersDiv.innerHTML = `<h3>Banners</h3><pre>${JSON.stringify(res.banners, null, 2)}</pre>`;
  reportLink.href = `/${data.report}`;
}

scanBtn.addEventListener("click", startScan);
