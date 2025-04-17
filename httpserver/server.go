package httpserver

import "github.com/gin-gonic/gin"

type Server struct {
	Engine  *gin.Engine
	address string
}

func New(address string) *Server {
	s := &Server{address: address}
	s.Engine = gin.Default()
	return s
}

func (s *Server) Run() {
	go s.Engine.Run(s.address)
}
