async function scanURL() {
  const url = document.getElementById('urlInput').value;
  document.getElementById('loadingPanel').style.display = 'block';  // show spinner

  const res = await fetch('/scan/url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });

  const data = await res.json();
  document.getElementById('loadingPanel').style.display = 'none';  // hide spinner
  document.getElementById('resultBox').innerHTML =
    `<strong>Result:</strong> ${data.final_result} <br>
     <strong>Rule:</strong> ${data.rule_based_result} <br>
     <strong>VirusTotal:</strong> ${data.virustotal_result}`;
}

async function scanEmail() {
  const email = document.getElementById('emailInput').value;
  document.getElementById('loadingPanel').style.display = 'block';
  const res = await fetch('/scan/email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });

  const data = await res.json();
  document.getElementById('loadingPanel').style.display = 'none';
  document.getElementById('resultBox').innerHTML =
    `<strong>Result:</strong> ${data.final_result} <br>
     <strong>Rule:</strong> ${data.rule_based_result} <br>
     <strong>ML:</strong> ${data.ml_result || 'N/A'}`;
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
