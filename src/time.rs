use core::future::Future;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonoTime(u64);

pub type TimeSpan = core::time::Duration;

impl MonoTime {
    pub const ZERO: Self = Self(0);

    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    pub const fn as_micros(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, span: TimeSpan) -> Option<Self> {
        let micros = u64::try_from(span.as_micros()).ok()?;
        self.0.checked_add(micros).map(Self)
    }

    pub(crate) fn duration_since(self, earlier: Self) -> TimeSpan {
        TimeSpan::from_micros(self.0 - earlier.0)
    }

    pub fn checked_duration_since(self, earlier: Self) -> Option<TimeSpan> {
        self.0.checked_sub(earlier.0).map(TimeSpan::from_micros)
    }
}

pub trait Clock {
    type Sleep<'a>: Future<Output = ()> + Send + 'a
    where
        Self: 'a;

    fn now(&self) -> MonoTime;
    fn sleep_until(&self, deadline: MonoTime) -> Self::Sleep<'_>;
}

#[cfg(feature = "embassy-clock")]
#[derive(Clone, Copy, Default)]
pub struct EmbassyClock;

#[cfg(feature = "embassy-clock")]
impl Clock for EmbassyClock {
    type Sleep<'a> = embassy_time::Timer;

    fn now(&self) -> MonoTime {
        MonoTime::from_micros(embassy_time::Instant::now().as_micros())
    }

    fn sleep_until(&self, deadline: MonoTime) -> Self::Sleep<'_> {
        embassy_time::Timer::at(embassy_time::Instant::from_micros(deadline.as_micros()))
    }
}
