#!/usr/bin/env python3
"""
Create favicon.ico from Dilithion logo
Generates multiple sizes for best browser compatibility
"""

from PIL import Image

# Load the logo
logo_path = 'website/Dilithion Logo.png'
output_path = 'website/favicon.ico'

print("Loading logo...")
img = Image.open(logo_path)

# Convert to RGBA if needed
if img.mode != 'RGBA':
    img = img.convert('RGBA')

# Create multiple sizes for the favicon (16x16, 32x32, 48x48)
sizes = [(16, 16), (32, 32), (48, 48)]
icons = []

for size in sizes:
    resized = img.resize(size, Image.Resampling.LANCZOS)
    icons.append(resized)
    print(f"Created {size[0]}x{size[1]} icon")

# Save as favicon.ico with multiple sizes
print(f"Saving favicon to {output_path}...")
icons[0].save(output_path, format='ICO', sizes=[icon.size for icon in icons], append_images=icons[1:])

print("✅ Favicon created successfully!")

# Also create a larger PNG version for Open Graph / social media
print("\nCreating logo-256.png for social media...")
img_256 = img.resize((256, 256), Image.Resampling.LANCZOS)
img_256.save('website/dilithion-logo-256.png')
print("✅ Created 256x256 PNG for social media")

print("\nFavicon and logo files ready!")
