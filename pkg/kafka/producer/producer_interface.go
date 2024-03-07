package producer

type IProducer interface {
	SendMessage(message string) (partition int32, offset int64, err error)
	Close() error
}
