const sampleInput = {
  ticket_id: 'TKT-DEMO-001',
  complaint: 'I tried to pay 1200 taka for my mobile recharge but the app showed failed. But my balance was deducted! Please refund my money.',
  language: 'en',
  channel: 'in_app_chat',
  user_type: 'customer',
  transaction_history: [
    {
      transaction_id: 'TXN-DEMO-9301',
      timestamp: '2026-04-14T16:25:00Z',
      type: 'payment',
      amount: 1200,
      counterparty: 'MOBILE_RECHARGE',
      status: 'failed'
    }
  ]
};

const apiBase = document.querySelector('#apiBase');
const healthBtn = document.querySelector('#healthBtn');
const healthStatus = document.querySelector('#healthStatus');
const sampleBtn = document.querySelector('#sampleBtn');
const submitBtn = document.querySelector('#submitBtn');
const requestBody = document.querySelector('#requestBody');
const responseBox = document.querySelector('#responseBox');
const httpStatus = document.querySelector('#httpStatus');
const latency = document.querySelector('#latency');

requestBody.value = JSON.stringify(sampleInput, null, 2);

function baseUrl() {
  return apiBase.value.trim().replace(/\/$/, '') || window.location.origin;
}

function showResponse(statusText, body, isError = false) {
  httpStatus.textContent = statusText;
  httpStatus.className = `badge${isError ? ' error' : ''}`;
  responseBox.textContent = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
}

sampleBtn.addEventListener('click', () => {
  requestBody.value = JSON.stringify(sampleInput, null, 2);
});

healthBtn.addEventListener('click', async () => {
  healthBtn.disabled = true;
  healthStatus.textContent = 'Checking...';
  try {
    const started = performance.now();
    const res = await fetch(`${baseUrl()}/health`);
    const data = await res.json();
    const ms = Math.round(performance.now() - started);
    healthStatus.textContent = `${res.status} ${res.statusText} · ${ms} ms · ${JSON.stringify(data)}`;
  } catch (error) {
    healthStatus.textContent = `Health check failed: ${error.message}`;
    healthStatus.className = 'muted error';
  } finally {
    healthBtn.disabled = false;
  }
});

submitBtn.addEventListener('click', async () => {
  let payload;
  latency.textContent = '';
  submitBtn.disabled = true;

  try {
    payload = JSON.parse(requestBody.value);
  } catch (error) {
    showResponse('invalid json', `Request JSON parse error: ${error.message}`, true);
    submitBtn.disabled = false;
    return;
  }

  try {
    const started = performance.now();
    const res = await fetch(`${baseUrl()}/analyze-ticket`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const text = await res.text();
    const ms = Math.round(performance.now() - started);
    latency.textContent = `${ms} ms`;

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    showResponse(`${res.status} ${res.statusText}`, data, !res.ok);
  } catch (error) {
    showResponse('network error', error.message, true);
  } finally {
    submitBtn.disabled = false;
  }
});
