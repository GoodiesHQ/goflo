package utils

func Ptr[T any](v T) *T {
	return &v
}

func DefaultIfNil[T any](ptr *T, defaultVal T) T {
	if ptr == nil {
		return defaultVal
	}
	return *ptr
}
