import streamlit as st
import string
import numpy as np
import re

def detect_file_type(text):
    if not text:
        return "unknown"
    unusual = sum(1 for c in text if ord(c) < 32 or ord(c) > 126)
    ratio = unusual / len(text) if text else 0
    
    byte_counts = {}
    for byte in text.encode('utf-8', errors='ignore'):
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    entropy = 0
    total = sum(byte_counts.values())
    for count in byte_counts.values():
        if count > 0:
            p = count / total
            entropy -= p * np.log2(p)
    
    if ratio > 0.3 or entropy > 7.0:
        return "encrypted"
    return "plaintext"

def vigenere_process(text, key, encrypt=True):
    result = ""
    details = [f"Key: {key} (length: {len(key)})\n"]
    key_idx = 0
    
    for i, char in enumerate(text):
        k_char = key[key_idx % len(key)]
        # Gunakan ASCII value langsung dari karakter key (huruf kecil atau besar)
        shift = ord(k_char.upper()) - 65
        
        if encrypt:
            new_val = (ord(char) + shift) % 256
            op = "+"
        else:
            new_val = (ord(char) - shift) % 256
            op = "-"
        
        new_char = chr(new_val)
        if i < 20:
            details.append(f"{repr(char)}({ord(char)}) {op} {k_char.upper()}({shift}) = {repr(new_char)}({new_val})")
        result += new_char
        key_idx += 1
    
    if len(text) > 20:
        details.append(f"\n... +{len(text) - 20} more")
    return result, details

def caesar_process(text, shift, encrypt=True):
    if not encrypt:
        shift = -shift
    result = ""
    details = []
    
    for i, char in enumerate(text):
        new_val = (ord(char) + shift) % 256
        new_char = chr(new_val)
        if i < 20:
            details.append(f"{repr(char)}({ord(char)}) → {repr(new_char)}({new_val})")
        result += new_char
    
    if len(text) > 20:
        details.append(f"... +{len(text) - 20} more")
    return result, details

def lfsr_cipher(text, seed, taps):
    state = list(map(int, bin(seed)[2:].zfill(8)))
    details = [f"Initial State: {''.join(map(str, state))}\n"]
    
    keystream_bits = []
    for i in range(len(text) * 8):
        output_bit = state[-1]
        keystream_bits.append(output_bit)
        
        feedback = 0
        for tap in taps:
            feedback ^= state[tap]
        
        state = [feedback] + state[:-1]
        
        if i < 15:
            details.append(f"Step {i+1}: {''.join(map(str, state))} → bit: {output_bit}")
    
    if len(text) * 8 > 15:
        details.append(f"... +{len(text) * 8 - 15} more steps\n")
    
    result = ""
    details.append("XOR Process (8 bits = 1 byte per char):")
    
    for i, char in enumerate(text):
        start_bit = i * 8
        key_byte = 0
        
        for j in range(8):
            key_byte = (key_byte << 1) | keystream_bits[start_bit + j]
        
        encrypted_val = ord(char) ^ key_byte
        encrypted_char = chr(encrypted_val)
        result += encrypted_char
        
        if i < 15:
            bits_str = ''.join(map(str, keystream_bits[start_bit:start_bit+8]))
            details.append(f"{repr(char)}({ord(char)}) ⊕ {bits_str}({key_byte}) = {repr(encrypted_char)}({encrypted_val})")
    
    if len(text) > 15:
        details.append(f"... +{len(text) - 15} more characters")
    
    return result, details

st.set_page_config(page_title="Aplikasi Kriptografi", page_icon="🔐", layout="centered")

st.markdown("""<style>
.main-header{font-size:2rem;font-weight:600;margin-bottom:0.5rem;color:#1f2937}
.sub-header{font-size:0.9rem;color:#6b7280;margin-bottom:2rem}
.stButton button{border-radius:8px;height:3rem;font-weight:500}
.file-badge{display:inline-block;padding:0.25rem 0.75rem;border-radius:6px;font-size:0.85rem;font-weight:500;margin-top:0.5rem}
.badge-plaintext{background-color:#dcfce7;color:#166534}
.badge-encrypted{background-color:#dbeafe;color:#1e40af}
</style>""", unsafe_allow_html=True)

st.markdown('<div class="main-header">Aplikasi Kriptografi</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Vigenere → Caesar → Stream LFSR</div>', unsafe_allow_html=True)

LFSR_TAPS = [0, 2, 3, 4] 

with st.expander("Setting Key", expanded=True):
    vigenere_key = st.text_input("Vigenere Key", value="rahasia", help="Key untuk Vigenere cipher")
    col1, col2 = st.columns(2)
    with col1:
        caesar_shift = st.number_input("Caesar Shift", 1, 25, 3, help="Nilai pergeseran (1-25)")
    with col2:
        lfsr_seed = st.number_input("LFSR Seed", 1, 255, 42, help="(1-255)")

lfsr_taps = LFSR_TAPS

uploaded_file = st.file_uploader("Upload TXT File", type=['txt'])

if uploaded_file:
    content = uploaded_file.read().decode('utf-8')
    file_type = detect_file_type(content)
    
    badge_class = "badge-plaintext" if file_type == "plaintext" else "badge-encrypted"
    icon = "📄" if file_type == "plaintext" else "🔒"
    st.markdown(f'{icon} {uploaded_file.name} <span class="file-badge {badge_class}">{file_type.upper()}</span>', unsafe_allow_html=True)
    
    st.session_state.update({'file_content': content, 'file_type': file_type, 'file_name': uploaded_file.name})
    st.markdown("<br>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    encrypt_btn = col1.button(" Enkripsi", type="primary", use_container_width=True)
    decrypt_btn = col2.button(" Dekripsi", use_container_width=True)
    
    if encrypt_btn:
        if file_type == "encrypted":
            st.error("⚠️ File sudah terenkripsi! Silakan upload file plaintext untuk enkripsi.")
        else:
            with st.spinner("Encrypting..."):
                v_result, v_details = vigenere_process(content, vigenere_key, True)
                c_result, c_details = caesar_process(v_result, caesar_shift, True)
                final, l_details = lfsr_cipher(c_result, lfsr_seed, lfsr_taps)
                
                st.success("✓ Enkripsi Berhasil")
                
                with st.expander("View Process"):
                    tab1, tab2, tab3 = st.tabs(["Vigenere", "Caesar", "LFSR"])
                    tab1.code("\n".join(v_details), language="text")
                    tab2.code("\n".join(c_details), language="text")
                    tab3.code("\n".join(l_details), language="text")
                
                st.download_button("↓ Download", final, f"encrypted_{uploaded_file.name}", "text/plain", use_container_width=True)
                st.session_state['encrypted'] = final
    
    if decrypt_btn:
        if file_type == "plaintext":
            st.error("⚠️ File adalah plaintext! Silakan upload file terenkripsi untuk dekripsi.")
        else:
            with st.spinner("Decrypting..."):
                l_result, l_details = lfsr_cipher(content, lfsr_seed, lfsr_taps)
                c_result, c_details = caesar_process(l_result, caesar_shift, False)
                final, v_details = vigenere_process(c_result, vigenere_key, False)
                
                st.success("✓ Dekripsi Berhasil")
                
                with st.expander("View Process"):
                    tab1, tab2, tab3 = st.tabs(["LFSR", "Caesar", "Vigenere"])
                    tab1.code("\n".join(l_details), language="text")
                    tab2.code("\n".join(c_details), language="text")
                    tab3.code("\n".join(v_details), language="text")
                
                st.download_button("↓ Download", final, f"decrypted_{uploaded_file.name}", "text/plain", use_container_width=True)
else:
    st.info("Upload file .txt untuk memulai")

st.markdown("---")