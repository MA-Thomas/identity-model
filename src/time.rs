use crate::fen::Timestamp;
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampParseError {
    MissingUtcSuffix,
    MissingDateTimeSeparator,
    InvalidDateComponent,
    InvalidTimeComponent,
    InvalidDate,
}

pub fn seconds_between(start: &Timestamp, end: &Timestamp) -> Result<i64, TimestampParseError> {
    Ok(timestamp_to_unix_seconds(end)? - timestamp_to_unix_seconds(start)?)
}

pub fn compare_timestamps(
    left: &Timestamp,
    right: &Timestamp,
) -> Result<Ordering, TimestampParseError> {
    Ok(timestamp_to_unix_seconds(left)?.cmp(&timestamp_to_unix_seconds(right)?))
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
    let value = timestamp_to_unix_seconds(value)?;
    let start = timestamp_to_unix_seconds(start)?;
    let end = timestamp_to_unix_seconds(end)?;
    Ok(start <= value && value <= end)
}

pub fn timestamp_to_unix_seconds(timestamp: &Timestamp) -> Result<i64, TimestampParseError> {
    let value = timestamp
        .0
        .strip_suffix('Z')
        .ok_or(TimestampParseError::MissingUtcSuffix)?;
    let (date, time) = value
        .split_once('T')
        .ok_or(TimestampParseError::MissingDateTimeSeparator)?;
    let (year, month, day) = parse_date(date)?;
    let (hour, minute, second) = parse_time(time)?;

    let days = days_from_civil(year, month, day)?;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
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
