package core

//function to check if the hardening is done correctly
func (h *Hardening) Correct() byte {
	var res byte
	if h.routes_request_ok {
		res += 1
	}

	if h.send_nodes_ok {
		res += (1 << 1)
	}

	if h.testing_request {
		res += (1 << 2)
	}

	return res
}
