use std::time::Duration;

use humanize_duration::{FormattedDuration, Truncate, prelude::DurationExt};

pub fn format_duration(duration: Duration) -> FormattedDuration {
    if duration.as_secs() < 60 {
        duration.human(Truncate::Second)
    } else if duration.as_secs() < 60 * 60 {
        duration.human(Truncate::Minute)
    } else if duration.as_secs() < 60 * 60 * 24 {
        duration.human(Truncate::Hour)
    } else if duration.as_secs() < 60 * 60 * 24 * 30 {
        duration.human(Truncate::Day)
    } else if duration.as_secs() < 60 * 60 * 24 * 365 {
        duration.human(Truncate::Month)
    } else {
        duration.human(Truncate::Year)
    }
}
