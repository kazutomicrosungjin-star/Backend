function normalizePhoneNumber(to) {
  if (typeof to !== 'string') throw new Error('SMS send failed');
  if (/^09\d{9}$/.test(to)) return `63${to.slice(1)}`;
  if (/^\+639\d{9}$/.test(to)) return to.slice(1);
  throw new Error('SMS send failed');
}

async function sendSms(to, text) {
  try {
    const token = process.env.MOCEAN_API_TOKEN;
    if (!token) throw new Error('SMS send failed');

    const form = new URLSearchParams({
      'mocean-from': process.env.MOCEAN_SENDER || 'MOCEAN',
      'mocean-to': normalizePhoneNumber(to),
      'mocean-text': text,
      'mocean-resp-format': 'json',
    });
    const res = await fetch('https://rest.moceanapi.com/rest/2/sms', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form,
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    if (!res.ok || data?.messages?.[0]?.status !== 0) {
      throw new Error('SMS send failed');
    }
    return { delivered: true, dev: false };
  } catch {
    throw new Error('SMS send failed');
  }
}

module.exports = { sendSms };
