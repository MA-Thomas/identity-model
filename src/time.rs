use crate::fen::Timestamp;

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
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
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
