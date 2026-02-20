### Deployment Instructions

1.  **Save the Script:**
    Save the code above as `install_gateway_phi3.sh` on your Debian VPS.

2.  **Make Executable:**
    ```bash
    chmod +x install_gateway_phi3.sh
    ```

3.  **Execute:**
    ```bash
    sudo ./install_gateway_phi3.sh
    ```

4.  **Verify Model Loading:**
    Once installed, verify that Phi-3-mini is loaded and responding quickly:
    ```bash
    curl -X POST http://127.0.0.1:11434/api/generate \
      -H "Content-Type: application/json" \
      -d '{"model": "phi3:mini", "prompt": "<|user|>Classify: Win money now!<|end|>\n<|assistant|>", "stream": false}'
    ```

### Technical Justification for This Configuration

1.  **Memory Efficiency:** Phi-3-mini requires approximately 2.5GB of RAM when quantized (Q4), allowing you to run this solution on a 4GB VPS comfortably, whereas Llama 3 would require 16GB.
2.  **Latency:** Classification time is reduced from ~5 seconds to ~1–2 seconds per email, significantly lowering the risk of SMTP timeouts.
3.  **Prompt Engineering:** The script now utilizes the specific Phi-3 chat template (`<|user|>...<|end|>\n<|assistant|>`), which ensures the model adheres strictly to the classification instruction without unnecessary conversational filler.

This solution is now optimised for cost-efficiency and performance while retaining the multi-tenant architecture you require.