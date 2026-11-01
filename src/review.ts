// src/review.ts
/**
 * When a declaration stops covering its finding. The event that ends a
 * reason is stated either in words ("a release of the library that fixes
 * the advisory") — people judge it, so it never ends by the clock — or as
 * a date (ISO 8601: YYYY-MM-DD, or a date with its time), and then the
 * declaration covers the finding until that moment and no longer: from
 * then on the finding is undeclared again, for every judge that reads the
 * file — a kept risk has an end, not a reminder that can be ignored. A
 * date that is no date is refused when the file is read, never taken as
 * words: an expiry misread as everlasting is the hole a date closes.
 */

/** A review event stated as a date: a calendar date, or a date with its time. */
const REVIEW_DATE = /^\d{4}-\d{2}-\d{2}(T.+)?$/;

/** The moment a review event comes (epoch ms), or null for an event in words. */
export function reviewDate(reviewWhen: string): number | null {
  if (!REVIEW_DATE.test(reviewWhen)) return null;
  const moment = Date.parse(reviewWhen);
  if (Number.isNaN(moment)) throw new RangeError(`"${reviewWhen}" is written as a date and is no date`);
  return moment;
}

/** Whether a declaration's review event has come by `now`: only a date comes by itself. */
export function isReviewDue(reviewWhen: string, now: Date): boolean {
  const moment = reviewDate(reviewWhen);
  return moment !== null && moment <= now.getTime();
}
