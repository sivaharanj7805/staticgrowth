terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  subscription_id = "5c6145d4-cca6-4da7-ad6c-83db5c8698df"
  features {}
}

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------

resource "azurerm_resource_group" "sentinel" {
  name     = var.resource_group_name
  location = var.location
}

# ---------------------------------------------------------------------------
# Networking — VNet, Subnet, NSG (locked down)
# ---------------------------------------------------------------------------

resource "azurerm_virtual_network" "sentinel" {
  name                = "vnet-ai-sentinel"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
}

resource "azurerm_subnet" "sentinel" {
  name                 = "subnet-ai-sentinel"
  resource_group_name  = azurerm_resource_group.sentinel.name
  virtual_network_name = azurerm_virtual_network.sentinel.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "sentinel" {
  name                = "nsg-ai-sentinel"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name

  # ALLOW: API access on port 8000 only
  security_rule {
    name                       = "AllowAPI"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8000"
    source_address_prefix      = var.allowed_ip
    destination_address_prefix = "*"
  }

  # DENY: SSH — no one can access the code or shell into the VM
  security_rule {
    name                       = "DenySSH"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # DENY: RDP
  security_rule {
    name                       = "DenyRDP"
    priority                   = 210
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # DENY: everything else inbound
  security_rule {
    name                       = "DenyAllOther"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "sentinel" {
  subnet_id                 = azurerm_subnet.sentinel.id
  network_security_group_id = azurerm_network_security_group.sentinel.id
}

# ---------------------------------------------------------------------------
# Public IP
# ---------------------------------------------------------------------------

resource "azurerm_public_ip" "sentinel" {
  name                = "pip-ai-sentinel"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# ---------------------------------------------------------------------------
# NIC
# ---------------------------------------------------------------------------

resource "azurerm_network_interface" "sentinel" {
  name                = "nic-ai-sentinel"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.sentinel.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.sentinel.id
  }
}

# ---------------------------------------------------------------------------
# SSH Key (generated, but SSH is blocked by NSG — used only for VM creation)
# ---------------------------------------------------------------------------

resource "tls_private_key" "sentinel" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# ---------------------------------------------------------------------------
# Cloud-init — bootstraps Docker + builds & runs the container
# ---------------------------------------------------------------------------

locals {
  cloud_init = <<-CLOUDINIT
    #cloud-config
    package_update: true
    packages:
      - docker.io
      - git

    runcmd:
      - systemctl enable docker
      - systemctl start docker

      # Clone the repo
      - git clone https://github.com/sivaharanj7805/staticgrowth.git /opt/ai-sentinel

      # Build the Docker image
      - cd /opt/ai-sentinel && docker build -t ai-sentinel:latest .

      # Run the container — only port 8000 exposed
      - |
        docker run -d \
          --name ai-sentinel \
          --restart unless-stopped \
          -p 8000:8000 \
          -e OPENAI_API_KEY="${var.openai_api_key}" \
          -e OPENAI_MODEL="${var.openai_model}" \
          ai-sentinel:latest

      # Lock down the VM filesystem — remove git repo source after build
      - rm -rf /opt/ai-sentinel

      # Disable SSH service entirely
      - systemctl stop sshd
      - systemctl disable sshd
  CLOUDINIT
}

# ---------------------------------------------------------------------------
# Virtual Machine
# ---------------------------------------------------------------------------

resource "azurerm_linux_virtual_machine" "sentinel" {
  name                            = "vm-ai-sentinel"
  location                        = azurerm_resource_group.sentinel.location
  resource_group_name             = azurerm_resource_group.sentinel.name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  custom_data                     = base64encode(local.cloud_init)

  network_interface_ids = [
    azurerm_network_interface.sentinel.id,
  ]

  admin_ssh_key {
    username   = var.admin_username
    public_key = tls_private_key.sentinel.public_key_openssh
  }

  os_disk {
    name                 = "osdisk-ai-sentinel"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 64
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  tags = {
    project = "ai-sentinel"
    purpose = "api-service"
  }
}
