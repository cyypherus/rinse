#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonoTime(u64);

pub type TimeSpan = core::time::Duration;

impl MonoTime {
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
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
