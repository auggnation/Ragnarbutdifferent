#!/usr/bin/env python3
"""EPD hardware diagnostic: initialize display and draw a test pattern.

Usage:
  source ragnar-venv/bin/activate
  python scripts/test_epd.py

It will try common Waveshare modules (epd4in26, epd2in13) and print detailed errors.
"""
import sys
import time
from PIL import Image, ImageDraw, ImageFont

MODULES = [
    ('epd4in26', 'epd4in26'),
    ('epd2in13', 'epd2in13'),
    ('epd2in13_V2', 'epd2in13_V2'),
]

def try_import(name):
    try:
        mod = __import__("waveshare_epd." + name, fromlist=['*'])
        return mod
    except Exception as e:
        print(f"Import failed for waveshare_epd.{name}: {e}")
        return None


def main():
    epd_mod = None
    epd_name = None
    for display_key, name in MODULES:
        print(f"Trying module: waveshare_epd.{name}")
        m = try_import(name)
        if m:
            epd_mod = m
            epd_name = name
            break

    if not epd_mod:
        print("No Waveshare EPD Python module found. Ensure the waveshare driver is installed in the active environment.")
        sys.exit(2)

    try:
        EPD = getattr(epd_mod, 'EPD') if hasattr(epd_mod, 'EPD') else getattr(epd_mod, 'epd4in26', None)
    except Exception:
        EPD = None

    try:
        # Some modules expose named constructors (example: epd4in26.EPD())
        epd = None
        try:
            epd = epd_mod.epd4in26.EPD() if hasattr(epd_mod, 'epd4in26') else None
        except Exception:
            pass

        if not epd and hasattr(epd_mod, 'EPD'):
            epd = epd_mod.EPD()

        if not epd:
            # Last resort: try a name-based lookup
            for attr in dir(epd_mod):
                if attr.lower().startswith('epd'):
                    try:
                        epd = getattr(epd_mod, attr)()
                        break
                    except Exception:
                        continue

        if not epd:
            print("Unable to construct EPD instance from module; aborting.")
            sys.exit(3)

        print(f"Using driver: waveshare_epd.{epd_name} -> {epd}")
        print("Initializing display...")
        epd.init()
        print("Clearing display... (this may take a few seconds)")
        epd.Clear()

        # Build a test image the size of the display
        width = getattr(epd, 'width', None) or getattr(epd, 'EPD_WIDTH', None) or 400
        height = getattr(epd, 'height', None) or getattr(epd, 'EPD_HEIGHT', None) or 300
        print(f"EPD size detected: {width}x{height}")

        image = Image.new('1', (width, height), 255)  # 1-bit, white
        draw = ImageDraw.Draw(image)

        # Draw checkerboard / dotted pattern to detect dead pixels
        box = 10
        for y in range(0, height, box):
            for x in range(0, width, box):
                if (x // box + y // box) % 2 == 0:
                    draw.rectangle([x, y, x + box - 1, y + box - 1], fill=0)

        # Add text with timestamp
        try:
            font = ImageFont.load_default()
            draw.text((5, 5), f"EPD test: {time.strftime('%Y-%m-%d %H:%M:%S')}", font=font, fill=255)
        except Exception:
            pass

        print("Displaying test image")
        try:
            epd.display(epd.getbuffer(image))
        except AttributeError:
            # Older driver APIs use display(image)
            try:
                epd.display(image)
            except Exception as e:
                print(f"Display call failed: {e}")

        print("Waiting 10 seconds to observe the display...")
        time.sleep(10)

        print("Attempting a full clear and sleep...")
        try:
            epd.Clear()
        except Exception:
            pass
        try:
            epd.sleep()
        except Exception:
            pass

        print("EPD test completed successfully (no driver exception). If the screen is still black/dotted, check wiring, power (3.3V), and ribbon connectors.")

    except Exception as e:
        print(f"EPD operation failed: {e}")
        sys.exit(4)

if __name__ == '__main__':
    main()
