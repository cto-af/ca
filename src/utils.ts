const HOUR_ms = 60 * 60 * 1000;
const DAY_ms = 24 * HOUR_ms;

/**
 * Get a date N days in the future.
 *
 * @param days How many days from now?
 * @param [now=new Date()] Starting when? (default: now).
 * @returns New date.
 */
export function daysFromNow(days: number, now = new Date()): Date {
  return new Date(now.getTime() + (days * DAY_ms));
}
