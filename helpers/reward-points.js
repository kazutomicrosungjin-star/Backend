const {
  POINTS_PER_PESO_EARN,
  DAILY_EARN_CAP_POINTS,
} = require('../config/rewards');

async function awardPoints(conn, userId, sourceType, sourceId, amountCentavos) {
  const points = Math.floor(amountCentavos / 100) * POINTS_PER_PESO_EARN;
  if (points <= 0) return;

  const [[row]] = await conn.query(
    `SELECT COALESCE(SUM(points), 0) AS earnedToday
       FROM reward_points_ledger
      WHERE user_id = ? AND points > 0
        AND created_at >= CURDATE()
        AND created_at < CURDATE() + INTERVAL 1 DAY`,
    [userId]
  );
  const earnedToday = Number(row.earnedToday);
  if (!Number.isSafeInteger(earnedToday) || earnedToday < 0) {
    throw new Error('Invalid daily reward points total');
  }

  const pointsToAward = Math.min(points, Math.max(0, DAILY_EARN_CAP_POINTS - earnedToday));
  if (pointsToAward <= 0) return;

  await conn.execute(
    'INSERT IGNORE INTO reward_points_ledger (user_id, points, source_type, source_id) VALUES (?,?,?,?)',
    [userId, pointsToAward, sourceType, String(sourceId)]
  );
}

module.exports = { awardPoints };
