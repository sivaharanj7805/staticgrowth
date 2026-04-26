output "api_url" {
  description = "The public URL for the AI Sentinel API"
  value       = "http://${azurerm_public_ip.sentinel.ip_address}:8000"
}

output "api_health_check" {
  description = "Health check endpoint to verify the API is running"
  value       = "http://${azurerm_public_ip.sentinel.ip_address}:8000/api/v1/health"
}

output "api_docs" {
  description = "Swagger UI for interactive API docs"
  value       = "http://${azurerm_public_ip.sentinel.ip_address}:8000/docs"
}

output "vm_public_ip" {
  description = "Public IP of the VM"
  value       = azurerm_public_ip.sentinel.ip_address
}
