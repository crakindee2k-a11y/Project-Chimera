const path = require('path');
const express = require('express');
const cors = require('cors');
const { analyzeTicket } = require('./analyzer');
const { parseTicketInput, validateAnalysisOutput, fallbackOutput } = require('./schema');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.post('/analyze-ticket', (req, res) => {
  const body = req.body;

  // Structurally invalid body (not a JSON object) -> 400.
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(fallbackOutput('unknown', 'invalid_request'));
  }

  const ticketPresent = body.ticket_id != null && String(body.ticket_id).trim() !== '';
  const ticketId = ticketPresent ? String(body.ticket_id).trim() : 'unknown';
  const complaintPresent = Object.prototype.hasOwnProperty.call(body, 'complaint');

  // Required keys present but complaint is semantically empty -> 422 (unprocessable),
  // distinct from a malformed/missing-field request which is 400.
  if (ticketPresent && complaintPresent && String(body.complaint ?? '').trim() === '') {
    return res.status(422).json(fallbackOutput(ticketId, 'empty_complaint'));
  }

  const parsed = parseTicketInput(body);
  if (!parsed.success) {
    return res.status(400).json(fallbackOutput(ticketId, 'invalid_request'));
  }

  const analysis = analyzeTicket(parsed.data);
  const validated = validateAnalysisOutput(analysis);
  if (!validated.success) {
    return res.status(500).json(fallbackOutput(parsed.data.ticket_id, 'output_validation_failed'));
  }

  return res.json(validated.data);
});

app.use((err, _req, res, _next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json(fallbackOutput('unknown', 'payload_too_large'));
  }
  // Malformed JSON body -> 400 (client error), never 500.
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
    return res.status(400).json(fallbackOutput('unknown', 'malformed_json'));
  }
  return res.status(500).json(fallbackOutput('unknown', 'server_error'));
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`QueueStorm Investigator listening on ${PORT}`);
  });
}

module.exports = app;
