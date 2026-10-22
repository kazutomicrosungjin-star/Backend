// Sends a text message. Pick a provider with environment variables:
//   SEMAPHORE_API_KEY  -> real SMS to Philippine numbers through semaphore.co
//                         (optional SEMAPHORE_SENDER_NAME, must be approved by Semaphore)
//   nothing set        -> "dev mode" only when OTP_DEV_MODE=true: the code is printed
//                         in the server log and returned to the app so you can demo
//                         the flow without paying for SMS.
const SEMAPHORE_API_KEY = process.env.SEMAPHORE_API_KEY || '';
const SEMAPHORE_SENDER_NAME = process.env.SEMAPHORE_SENDER_NAME || '';
const OTP_DEV_MODE = process.env.OTP_DEV_MODE === 'true';

const smsIsReal = Boolean(SEMAPHORE_API_KEY);

async function sendSms(phoneNumber, message) {
  if (!smsIsReal) {
    if (OTP_DEV_MODE) {
      console.log(`[SMS dev mode] to ${phoneNumber}: ${message}`);
    }
    return { delivered: false, dev: true };
  }
  const form = new URLSearchParams({ apikey: SEMAPHORE_API_KEY, number: phoneNumber, message });
  if (SEMAPHORE_SENDER_NAME) form.set('sendername', SEMAPHORE_SENDER_NAME);
  // /priority is the same as /messages but skips the normal queue (better for codes).
  const res = await fetch('https://api.semaphore.co/api/v4/priority', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) {
    await res.text().catch(() => '');
    throw new Error(`Semaphore error ${res.status}`);
  }
  return { delivered: true, dev: false };
}

module.exports = { sendSms, smsIsReal };
