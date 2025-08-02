function clearResultBox() {
  const box = document.getElementById("resultBox");
  box.className = "alert alert-secondary mt-3";
  box.style.display = "none";
  box.innerHTML = "";
}

function showLoading(show = true) {
  document.getElementById("loadingPanel").style.display = show ? "block" : "none";
}

function displayResult(type, result, details) {
  const box = document.getElementById("resultBox");

  let color = "secondary";
  if (result === "Safe") color = "success";
  else if (result === "Suspicious") color = "warning text-dark";
  else if (result === "Malicious") color = "danger";

  box.className = `alert alert-${color} mt-3`;
  box.style.display = "block";
  box.innerHTML = `
    <h5>Result: ${result}</h5>

    <p><strong>Type:</strong> ${type}</p>
    ${details}
  `;
}

async function scanURL() {
  const url = document.getElementById('urlInput').value;
  if (!url) return alert("Please enter a URL.");

  clearResultBox();
  showLoading(true);

  try {
    const res = await fetch('/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await res.json();
    showLoading(false);

    const details = `
      <p><strong>Rule-based:</strong> ${data.rule_based_result}</p>
      <p><strong>VirusTotal:</strong> ${data.virustotal_result}</p>
    `;
    displayResult("URL", data.final_result, details);
  } catch (err) {
    showLoading(false);
    alert("Error: " + err.message);
  }
}

async function scanEmail() {
  const email = document.getElementById('emailInput').value;
  if (!email) return alert("Please enter email content.");

  clearResultBox();
  showLoading(true);

  try {
    const res = await fetch('/scan/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    const data = await res.json();
    showLoading(false);

    const details = `
      <p><strong>Rule-based:</strong> ${data.rule_based_result}</p>
      <p><strong>ML:</strong> ${data.ml_result}</p>
    `;
    displayResult("Email", data.final_result, details);
  } catch (err) {
    showLoading(false);
    alert("Error: " + err.message);
  }
}


async function loadHistory() {
  const res = await fetch('/history');
  const data = await res.json();
  const list = document.getElementById('historyList');
  list.innerHTML = "";
  data.reverse().forEach(entry => {
    const item = document.createElement('li');
    item.className = 'list-group-item';
    item.innerHTML = `[${entry.type.toUpperCase()}] <strong>${entry.final_result || entry.result}</strong> - ${entry.input.substring(0, 80)}...`;
    list.appendChild(item);
  });
}
