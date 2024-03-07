package consumer

type IConsumer interface {
	Consume() error
}
