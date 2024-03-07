package consumer

type Processor interface {
	Process(payload string) error
}
