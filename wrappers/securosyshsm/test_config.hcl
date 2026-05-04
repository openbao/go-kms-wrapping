storage "raft" {
  path = "./docker/db"
  node_id = "raft_node_1"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}
api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
ui = true

seal "securosys-hsm" {
  key_label = "replace_with_key_label"
  tsb_api_endpoint = "replace_with_tsb_api"
  auth = "NONE"
  key_password = ""
  check_every = 5
  approval_timeout = 3000
  policy = <<EOF
  { 
  }
  EOF
}
