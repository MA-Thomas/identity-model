use crate::fen::Timestamp;
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampParseError {
    MissingUtcSuffix,
    MissingDateTimeSeparator,
    InvalidDateComponent,
    InvalidTimeComponent,
    InvalidDate,
    InvalidFraction,
    InvalidUtcOffset,
}

/// A parsed, validated UTC timestamp.
///
/// `Timestamp` remains the boundary/storage representation (an RFC 3339
/// string). `UtcTimestamp` is what security-sensitive code should compare:
/// it is parsed once, normalized to UTC, and all comparisons are infallible.
///
/// The original string rendering is retained as `canonical` so that
/// signature verification and canonical serialization keep seeing exactly
/// the bytes a provider signed; equality, ordering, and hashing deliberately
/// ignore it and use only the normalized instant.
#[derive(Debug, Clone)]
pub struct UtcTimestamp {
    unix_seconds: i64,
    subsec_nanos: u32,
    canonical: String,
}

impl UtcTimestamp {
    /// Parses an RFC 3339 timestamp.
    ///
    /// Accepts fractional seconds and numeric UTC offsets (e.g.
    /// `2026-05-29T00:00:00Z`, `2026-05-29T00:00:00.250Z`,
    /// `2026-05-29T02:00:00+02:00`), normalizing offsets to UTC. The
    /// previous parser accepted only whole-second `Z` timestamps, which
    /// rejected legitimate provider evidence at comparison time.
    pub fn parse(value: &str) -> Result<Self, TimestampParseError> {
        let (datetime, offset_seconds) = split_offset(value)?;
        let (date, time_and_fraction) = datetime
            .split_once(['T', 't'])
            .ok_or(TimestampParseError::MissingDateTimeSeparator)?;
        let (time, fraction) = match time_and_fraction.split_once('.') {
            Some((time, fraction)) => (time, Some(fraction)),
            None => (time_and_fraction, None),
        };

        let (year, month, day) = parse_date(date)?;
        let (hour, minute, second) = parse_time(time)?;
        let subsec_nanos = match fraction {
            Some(fraction) => parse_fraction_nanos(fraction)?,
            None => 0,
        };

        let days = days_from_civil(year, month, day)?;
        let unix_seconds =
            days * 86_400 + hour * 3_600 + minute * 60 + second - i64::from(offset_seconds);

        Ok(Self {
            unix_seconds,
            subsec_nanos,
            canonical: value.to_string(),
        })
    }

    pub fn from_timestamp(timestamp: &Timestamp) -> Result<Self, TimestampParseError> {
        Self::parse(&timestamp.0)
    }

    pub fn from_unix_seconds(unix_seconds: i64) -> Self {
        let canonical = unix_seconds_to_timestamp(unix_seconds).0;
        Self {
            unix_seconds,
            subsec_nanos: 0,
            canonical,
        }
    }

    pub fn unix_seconds(&self) -> i64 {
        self.unix_seconds
    }

    pub fn subsec_nanos(&self) -> u32 {
        self.subsec_nanos
    }

    /// The original string this instant was parsed from. Canonical
    /// serialization and signed-assertion verification must use this,
    /// never a re-rendering.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn to_timestamp(&self) -> Timestamp {
        Timestamp(self.canonical.clone())
    }

    pub fn seconds_since(&self, earlier: &UtcTimestamp) -> i64 {
        self.unix_seconds - earlier.unix_seconds
    }

    pub fn is_after(&self, other: &UtcTimestamp) -> bool {
        self > other
    }

    pub fn is_before(&self, other: &UtcTimestamp) -> bool {
        self < other
    }

    pub fn is_at_or_after(&self, other: &UtcTimestamp) -> bool {
        self >= other
    }

    pub fn in_closed_interval(&self, start: &UtcTimestamp, end: &UtcTimestamp) -> bool {
        start <= self && self <= end
    }

    fn instant(&self) -> (i64, u32) {
        (self.unix_seconds, self.subsec_nanos)
    }
}

impl PartialEq for UtcTimestamp {
    fn eq(&self, other: &Self) -> bool {
        self.instant() == other.instant()
    }
}

impl Eq for UtcTimestamp {}

impl PartialOrd for UtcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UtcTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.instant().cmp(&other.instant())
    }
}

impl std::hash::Hash for UtcTimestamp {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.instant().hash(state);
    }
}

impl TryFrom<&Timestamp> for UtcTimestamp {
    type Error = TimestampParseError;

    fn try_from(timestamp: &Timestamp) -> Result<Self, Self::Error> {
        Self::from_timestamp(timestamp)
    }
}

impl From<UtcTimestamp> for Timestamp {
    fn from(value: UtcTimestamp) -> Self {
        Timestamp(value.canonical)
    }
}

pub fn seconds_between(start: &Timestamp, end: &Timestamp) -> Result<i64, TimestampParseError> {
    Ok(timestamp_to_unix_seconds(end)? - timestamp_to_unix_seconds(start)?)
}

pub fn compare_timestamps(
    left: &Timestamp,
    right: &Timestamp,
) -> Result<Ordering, TimestampParseError> {
    Ok(UtcTimestamp::from_timestamp(left)?.cmp(&UtcTimestamp::from_timestamp(right)?))
}

pub fn timestamp_at_or_after(
    left: &Timestamp,
    right: &Timestamp,
) -> Result<bool, TimestampParseError> {
    Ok(matches!(
        compare_timestamps(left, right)?,
        Ordering::Equal | Ordering::Greater
    ))
}

pub fn timestamp_after(left: &Timestamp, right: &Timestamp) -> Result<bool, TimestampParseError> {
    Ok(compare_timestamps(left, right)? == Ordering::Greater)
}

pub fn timestamp_before(left: &Timestamp, right: &Timestamp) -> Result<bool, TimestampParseError> {
    Ok(compare_timestamps(left, right)? == Ordering::Less)
}

pub fn timestamp_in_closed_interval(
    value: &Timestamp,
    start: &Timestamp,
    end: &Timestamp,
) -> Result<bool, TimestampParseError> {
    let value = UtcTimestamp::from_timestamp(value)?;
    let start = UtcTimestamp::from_timestamp(start)?;
    let end = UtcTimestamp::from_timestamp(end)?;
    Ok(value.in_closed_interval(&start, &end))
}

pub fn timestamp_to_unix_seconds(timestamp: &Timestamp) -> Result<i64, TimestampParseError> {
    Ok(UtcTimestamp::from_timestamp(timestamp)?.unix_seconds())
}

pub fn unix_seconds_to_timestamp(seconds: i64) -> Timestamp {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    Timestamp(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Splits a trailing UTC designator or numeric offset from an RFC 3339
/// timestamp, returning the date-time portion and the offset in seconds.
fn split_offset(value: &str) -> Result<(&str, i32), TimestampParseError> {
    if let Some(datetime) = value.strip_suffix(['Z', 'z']) {
        return Ok((datetime, 0));
    }

    // A numeric offset is exactly six characters: sign, HH, ':', MM. Inspect
    // the tail as bytes first: only when the pattern matches (all ASCII) is
    // slicing the string at `len - 6` guaranteed to be safe.
    let bytes = value.as_bytes();
    if bytes.len() > 6 {
        let tail = &bytes[bytes.len() - 6..];
        if (tail[0] == b'+' || tail[0] == b'-')
            && tail[1].is_ascii_digit()
            && tail[2].is_ascii_digit()
            && tail[3] == b':'
            && tail[4].is_ascii_digit()
            && tail[5].is_ascii_digit()
        {
            let datetime = &value[..value.len() - 6];
            let offset = &value[value.len() - 6..];
            let hours: i32 = offset[1..3]
                .parse()
                .map_err(|_| TimestampParseError::InvalidUtcOffset)?;
            let minutes: i32 = offset[4..6]
                .parse()
                .map_err(|_| TimestampParseError::InvalidUtcOffset)?;
            if hours > 23 || minutes > 59 {
                return Err(TimestampParseError::InvalidUtcOffset);
            }
            let magnitude = hours * 3_600 + minutes * 60;
            let signed = if tail[0] == b'-' { -magnitude } else { magnitude };
            return Ok((datetime, signed));
        }
    }

    Err(TimestampParseError::MissingUtcSuffix)
}

fn parse_fraction_nanos(fraction: &str) -> Result<u32, TimestampParseError> {
    if fraction.is_empty()
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TimestampParseError::InvalidFraction);
    }

    let digits: u32 = fraction
        .parse()
        .map_err(|_| TimestampParseError::InvalidFraction)?;
    Ok(digits * 10_u32.pow(9 - fraction.len() as u32))
}

fn parse_date(date: &str) -> Result<(i64, i64, i64), TimestampParseError> {
    let mut date_parts = date.split('-');
    let year = parse_component(date_parts.next(), TimestampParseError::InvalidDateComponent)?;
    let month = parse_component(date_parts.next(), TimestampParseError::InvalidDateComponent)?;
    let day = parse_component(date_parts.next(), TimestampParseError::InvalidDateComponent)?;

    if date_parts.next().is_some() {
        return Err(TimestampParseError::InvalidDateComponent);
    }

    Ok((year, month, day))
}

fn parse_time(time: &str) -> Result<(i64, i64, i64), TimestampParseError> {
    let mut time_parts = time.split(':');
    let hour = parse_component(time_parts.next(), TimestampParseError::InvalidTimeComponent)?;
    let minute = parse_component(time_parts.next(), TimestampParseError::InvalidTimeComponent)?;
    let second = parse_component(time_parts.next(), TimestampParseError::InvalidTimeComponent)?;

    if time_parts.next().is_some()
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(TimestampParseError::InvalidTimeComponent);
    }

    Ok((hour, minute, second))
}

fn parse_component(
    component: Option<&str>,
    error: TimestampParseError,
) -> Result<i64, TimestampParseError> {
    component.ok_or(error)?.parse().map_err(|_| error)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Result<i64, TimestampParseError> {
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return Err(TimestampParseError::InvalidDate);
    }

    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    Ok(era * 146_097 + day_of_era - 719_468)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(value: &str) -> Timestamp {
        Timestamp(value.to_string())
    }

    #[test]
    fn parses_whole_second_utc_timestamps() {
        let parsed = UtcTimestamp::parse("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(parsed.unix_seconds(), 0);
        assert_eq!(parsed.subsec_nanos(), 0);
        assert_eq!(parsed.canonical(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn parses_fractional_seconds() {
        let parsed = UtcTimestamp::parse("2026-05-29T00:00:00.250Z").unwrap();
        assert_eq!(parsed.subsec_nanos(), 250_000_000);
        let whole = UtcTimestamp::parse("2026-05-29T00:00:00Z").unwrap();
        assert!(parsed > whole);
        assert_eq!(parsed.seconds_since(&whole), 0);
    }

    #[test]
    fn normalizes_numeric_offsets_to_utc() {
        let offset = UtcTimestamp::parse("2026-05-29T02:00:00+02:00").unwrap();
        let utc = UtcTimestamp::parse("2026-05-29T00:00:00Z").unwrap();
        assert_eq!(offset, utc);

        let negative = UtcTimestamp::parse("2026-05-28T19:00:00-05:00").unwrap();
        assert_eq!(negative, utc);
    }

    #[test]
    fn equality_ignores_rendering_but_keeps_canonical_bytes() {
        let left = UtcTimestamp::parse("2026-05-29T02:00:00+02:00").unwrap();
        let right = UtcTimestamp::parse("2026-05-29T00:00:00Z").unwrap();
        assert_eq!(left, right);
        assert_ne!(left.canonical(), right.canonical());
        assert_eq!(left.to_timestamp(), ts("2026-05-29T02:00:00+02:00"));
    }

    #[test]
    fn rejects_malformed_timestamps() {
        assert!(UtcTimestamp::parse("2026-05-29").is_err());
        assert!(UtcTimestamp::parse("2026-05-29T00:00:00").is_err());
        assert!(UtcTimestamp::parse("2026-05-29 00:00:00Z").is_err());
        assert!(UtcTimestamp::parse("2026-13-01T00:00:00Z").is_err());
        assert!(UtcTimestamp::parse("2026-02-30T00:00:00Z").is_err());
        assert!(UtcTimestamp::parse("2026-05-29T24:00:00Z").is_err());
        assert!(UtcTimestamp::parse("2026-05-29T00:00:00.Z").is_err());
        assert!(UtcTimestamp::parse("2026-05-29T00:00:00.1234567890Z").is_err());
        assert!(UtcTimestamp::parse("2026-05-29T00:00:00+25:00").is_err());
        assert!(UtcTimestamp::parse("not-a-timestamp").is_err());
    }

    #[test]
    fn comparison_helpers_agree_with_previous_semantics() {
        let earlier = ts("2026-05-29T00:00:00Z");
        let later = ts("2026-05-29T00:01:00Z");
        assert_eq!(seconds_between(&earlier, &later).unwrap(), 60);
        assert!(timestamp_after(&later, &earlier).unwrap());
        assert!(timestamp_before(&earlier, &later).unwrap());
        assert!(timestamp_at_or_after(&later, &earlier).unwrap());
        assert!(timestamp_at_or_after(&earlier, &earlier).unwrap());
        assert!(timestamp_in_closed_interval(&earlier, &earlier, &later).unwrap());
    }

    #[test]
    fn round_trips_unix_seconds() {
        let timestamp = ts("2026-06-12T08:30:45Z");
        let seconds = timestamp_to_unix_seconds(&timestamp).unwrap();
        assert_eq!(unix_seconds_to_timestamp(seconds), timestamp);
    }
}
