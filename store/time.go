package store

import "time"

// Time wraps time.Time so a zero timestamp marshals as "" rather than
// "0001-01-01T00:00:00Z". Gate CLIs emit entries as JSON, and an empty string
// reads better than a year-1 date for a field that was simply never set.
type Time struct {
	time.Time
}

func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte(`""`), nil
	}
	return []byte(`"` + t.UTC().Format(time.RFC3339Nano) + `"`), nil
}

func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == `""` || string(data) == `null` {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(`"`+time.RFC3339Nano+`"`, string(data))
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

func encodeTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func decodeTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
