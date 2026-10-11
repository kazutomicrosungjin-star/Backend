// Live "now showing" list for the app's Store, from The Movie Database (TMDB).
//
// Turn it on by setting TMDB_API_KEY (a free "API Key (v3 auth)" from
// https://www.themoviedb.org/settings/api). The answer is cached for 6 hours so
// the app never hammers TMDB, and an older copy is served if TMDB is down.
//
// TMDB knows what is playing in cinemas in a country, not each cinema's exact
// schedule, so showtimes are generated from the movie's running time. They are
// samples; the cinema decides the real ones.
const TMDB_API_KEY = process.env.TMDB_API_KEY || '';
const REGION = process.env.MOVIES_REGION || 'PH';
const TTL_MS = 6 * 60 * 60 * 1000;
const MAX_MOVIES = 12;
const POSTER_BASE = 'https://image.tmdb.org/t/p/w342';

const moviesEnabled = Boolean(TMDB_API_KEY);

let cache = null; // { at, data }
let inflight = null;

async function tmdb(path, params = {}) {
  const url = new URL(`https://api.themoviedb.org/3${path}`);
  url.searchParams.set('api_key', TMDB_API_KEY);
  url.searchParams.set('language', 'en-US');
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, String(value));
  const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`TMDB ${path} answered ${res.status}`);
  return res.json();
}

function formatClock(totalMinutes) {
  const h24 = Math.floor(totalMinutes / 60);
  const m = totalMinutes % 60;
  const h = h24 % 12 || 12;
  return `${h}:${String(m).padStart(2, '0')} ${h24 < 12 ? 'AM' : 'PM'}`;
}

// Back-to-back shows: running time + 30 minutes for trailers and cleaning,
// rounded up to 15. The first show shifts a little per movie so lists differ.
function showtimesFor(runtimeMinutes, id) {
  const slot = Math.ceil(((runtimeMinutes || 110) + 30) / 15) * 15;
  let start = 10 * 60 + 30 + (Number(id) % 3) * 15;
  const times = [];
  while (start <= 21 * 60 + 45 && times.length < 6) {
    times.push(formatClock(start));
    start += slot;
  }
  return times;
}

function formatDuration(runtimeMinutes) {
  if (!runtimeMinutes) return '';
  return `${Math.floor(runtimeMinutes / 60)}h ${String(runtimeMinutes % 60).padStart(2, '0')}m`;
}

function certificationFor(details) {
  const country = details?.release_dates?.results?.find((r) => r.iso_3166_1 === REGION);
  return country?.release_dates?.map((d) => d.certification).find(Boolean) || '';
}

async function build() {
  const [genreList, playing] = await Promise.all([
    tmdb('/genre/movie/list'),
    tmdb('/movie/now_playing', { region: REGION, page: 1 }),
  ]);
  const genreName = new Map((genreList.genres || []).map((g) => [g.id, g.name]));
  const picked = (playing.results || [])
    .filter((m) => m.poster_path)
    .sort((a, b) => b.popularity - a.popularity)
    .slice(0, MAX_MOVIES);

  const movies = await Promise.all(
    picked.map(async (m) => {
      let details = null;
      try {
        details = await tmdb(`/movie/${m.id}`, { append_to_response: 'release_dates' });
      } catch (_) {
        // Still show the movie without running time / rating.
      }
      const runtime = details?.runtime || 0;
      return {
        id: m.id,
        title: m.title,
        genre:
          (m.genre_ids || [])
            .slice(0, 2)
            .map((id) => genreName.get(id))
            .filter(Boolean)
            .join(' / ') || 'Movie',
        duration: formatDuration(runtime),
        rating: certificationFor(details),
        overview: m.overview || '',
        posterUrl: `${POSTER_BASE}${m.poster_path}`,
        releaseDate: m.release_date || '',
        showtimes: showtimesFor(runtime, m.id),
      };
    })
  );
  return { movies, source: 'tmdb', region: REGION, updatedAt: new Date().toISOString() };
}

async function getNowShowing() {
  if (!moviesEnabled) {
    const err = new Error('Live movies are not set up on this server');
    err.status = 503;
    throw err;
  }
  if (cache && Date.now() - cache.at < TTL_MS) return cache.data;
  if (!inflight) {
    inflight = build()
      .then((data) => {
        cache = { at: Date.now(), data };
        return data;
      })
      .catch((err) => {
        if (cache) return cache.data; // stale beats nothing
        throw err;
      })
      .finally(() => {
        inflight = null;
      });
  }
  return inflight;
}

module.exports = { getNowShowing, moviesEnabled };
