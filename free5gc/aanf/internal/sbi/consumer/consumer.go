package consumer

import (
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/app"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
)

type ConsumerAanf interface {
	app.App
}

type Consumer struct {
	ConsumerAanf

	*nnrfService
	*nudmService
}

func NewConsumer(aanf ConsumerAanf) (*Consumer, error) {
	c := &Consumer{
		ConsumerAanf: aanf,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfMngmntClients: make(map[string]*Nnrf_NFManagement.APIClient),
	}
	c.nudmService = &nudmService{consumer: c}

	return c, nil
}
