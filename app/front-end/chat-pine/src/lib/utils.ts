import { NextFont } from "next/dist/compiled/@next/font";

export function cn(
  ...classes: (string | undefined | null | boolean | NextFont)[]
): string {
  return classes.filter(Boolean).join(" ");
}
