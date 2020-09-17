package input

type ECSSession struct {
	RFCTimestamp string `json:"@timestamp"`
	Agent        struct {
		Hostname string
		ID       string
	}
	Source struct {
		IP      string
		Port    int
		Bytes   int64
		Packets int64
	}
	Destination struct {
		IP      string
		Port    int
		Bytes   int64
		Packets int64
	}
	Network struct {
		Transport string // RITA Proto
		Protocol  string // RITA Service
	}
	Event struct {
		Duration float64
	}
}
