package repositories

import "fmt"

type RecordNotFoundError[T any] struct {
	Model T
}

func NewRecordNotFoundError[T any](model T) RecordNotFoundError[T] {
	return RecordNotFoundError[T]{Model: model}
}

func (e RecordNotFoundError[T]) Error() string {
	return fmt.Sprintf("%v record not found", e.Model)
}
