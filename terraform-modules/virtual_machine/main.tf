resource "azurerm_public_ip" "vm_pip" {
  name                = var.vm_pip
  resource_group_name = var.rg_Name
  location            = var.location
  allocation_method   = var.pip_allocation
}

resource "azurerm_network_interface" "vm_nic" {
  name                = var.vm_nic
  resource_group_name = var.rg_Name
  location            = var.location

  ip_configuration {
    name                          = var.ip_configuration
    subnet_id                     = var.vm_subnetid
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm_pip.*.id
  }
}

# resource "azurerm_network_security_group" "webserver" {
#   name                = "tls_webserver"
#   location            = var.location
#   resource_group_name = var.rg_Name

#   security_rule {
#     access                     = "Allow"
#     direction                  = "Inbound"
#     name                       = "tls"
#     priority                   = 100
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     source_address_prefix      = "*"
#     destination_port_range     = "443"
#     destination_address_prefix = "*"
#   }

#   security_rule {
#     access                     = "Allow"
#     direction                  = "Inbound"
#     name                       = "ssh"
#     priority                   = 200
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     source_address_prefix      = "*"
#     destination_port_range     = "22"
#     destination_address_prefix = "*"
#   }
# }



# resource "azurerm_network_interface_security_group_association" "main" {
#   network_interface_id      = azurerm_network_interface.vm_nic.id
#   network_security_group_id = azurerm_network_security_group.webserver.id
# }
############################################
data "azurerm_key_vault" "hostkey_kv" {
  name                = "shankar-testkeyvault"
  resource_group_name = "1st"
}
data "azurerm_key_vault_secret" "ssh_host_rsa_key_pub" {
  name         = "ssh-host-rsa-key-pub"
  key_vault_id = data.azurerm_key_vault.hostkey_kv.id
}
data "azurerm_key_vault_secret" "ssh_host_rsa_key" {
  name         = "ssh-host-rsa-key"
  key_vault_id = data.azurerm_key_vault.hostkey_kv.id
}
data "azurerm_key_vault_secret" "ssh_host_ed25519_key_pub" {
  name         = "ssh-host-ed25519-key-pub"
  key_vault_id = data.azurerm_key_vault.hostkey_kv.id
}
data "azurerm_key_vault_secret" "ssh_host_ed25519_key" {
  name         = "ssh-host-ed25519-key"
  key_vault_id = data.azurerm_key_vault.hostkey_kv.id
}
data "azurerm_key_vault_secret" "ssh_host_ecdsa_key_pub" {
  name         = "ssh-host-ecdsa-key-pub"
  key_vault_id = data.azurerm_key_vault.hostkey_kv.id
}
data "azurerm_key_vault_secret" "ssh_host_ecdsa_key" {
  name         = "ssh-host-ecdsa-key"
  key_vault_id = data.azurerm_key_vault.hostkey_kv.id
}

locals {
  ssh_host_rsa_key_pub = data.azurerm_key_vault_secret.ssh_host_rsa_key_pub.value
ssh_host_rsa_key = data.azurerm_key_vault_secret.ssh_host_rsa_key.value
ssh_host_ed25519_key_pub = data.azurerm_key_vault_secret.ssh_host_ed25519_key_pub.value
ssh_host_ed25519_key = data.azurerm_key_vault_secret.ssh_host_ed25519_key.value
ssh_host_ecdsa_key_pub = data.azurerm_key_vault_secret.ssh_host_ecdsa_key_pub.value
ssh_host_ecdsa_key = data.azurerm_key_vault_secret.ssh_host_ecdsa_key.value
}

###########################################

resource "azurerm_linux_virtual_machine" "winvm" {
  name                = var.vm_name
  resource_group_name = var.rg_Name
  location            = var.location
  size                = var.vm_size
  admin_username      = var.vm_username

  admin_ssh_key {
    username = var.vm_username
    public_key = file(var.pubkey_path)
  }

  #disable_password_authentication = false
  network_interface_ids = [
    azurerm_network_interface.vm_nic.*.id,
  ]

  source_image_reference {
    publisher = "canonical"
    offer =  "0001-com-ubuntu-server-jammy"
    sku = "22_04-lts-gen2"
    version = "latest"
  }
  os_disk {
    caching = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb = 30
  }

  connection {
      type        = "ssh"
      user        = var.vm_username
      host        = azurerm_public_ip.vm_pip.ip_address
      private_key = file("${path.module}/id_rsa")
    }
    provisioner "remote-exec" {
    inline = [

        "sudo cat /dev/null > /etc/ssh/ssh_host_rsa_key.pub",
        "echo \"${local.ssh_host_rsa_key_pub}\" | sudo tee  /etc/ssh/ssh_host_rsa_key.pub> /dev/null",

        "sudo cat /dev/null > /etc/ssh/ssh_host_rsa_key",
        "echo \"${local.ssh_host_rsa_key}\" | sudo tee  /etc/ssh/ssh_host_rsa_key> /dev/null",

        "sudo cat /dev/null > /etc/ssh/ssh_host_ed25519_key.pub",
        "echo \"${local.ssh_host_ed25519_key_pub}\" | sudo tee  /etc/ssh/ssh_host_ed25519_key.pub> /dev/null",

        "sudo cat /dev/null > /etc/ssh/ssh_host_ed25519_key",
        "echo \"${local.ssh_host_ed25519_key}\" | sudo tee  /etc/ssh/ssh_host_ed25519_key> /dev/null",

        "sudo cat /dev/null > /etc/ssh/ssh_host_ecdsa_key.pub",
        "echo \"${local.ssh_host_ecdsa_key_pub}\" | sudo tee  /etc/ssh/ssh_host_ecdsa_key.pub> /dev/null",

        "sudo cat /dev/null > /etc/ssh/ssh_host_ecdsa_key",
        "echo \"${local.ssh_host_ecdsa_key}\" | sudo tee  /etc/ssh/ssh_host_ecdsa_key> /dev/null",  
    ]

  }
}


