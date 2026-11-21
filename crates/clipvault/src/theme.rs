//! The Mist theme: shadcn/ui preset `b3ezFPvD9s` (radix-vega, mist, Inter with
//! Geist headings) mapped onto gpui-component by `scripts/shadcn-theme.py`.
//!
//! The fonts are embedded so the app looks the same whatever is installed.

use std::borrow::Cow;

use gpui::{div, px, App, Div, FontWeight, ParentElement, Pixels, SharedString, Styled};
use gpui_component::{Theme, ThemeRegistry};

const THEMES: &str = include_str!("../../../assets/themes/mist.json");
const LIGHT: &str = "Mist Light";
const DARK: &str = "Mist Dark";

const FONTS: [&[u8]; 3] = [
    include_bytes!("../../../assets/fonts/inter/Inter-Regular.otf"),
    include_bytes!("../../../assets/fonts/inter/Inter-Medium.otf"),
    include_bytes!("../../../assets/fonts/geist/Geist-Medium.ttf"),
];

const HEADING_FONT: &str = "Geist";

/// Registers the fonts and makes Mist the light and dark theme. The mode is
/// applied when a window opens.
pub fn init(cx: &mut App) {
    let fonts = FONTS.iter().map(|f| Cow::Borrowed(*f)).collect();
    if let Err(e) = cx.text_system().add_fonts(fonts) {
        log::warn!("embedded fonts not loaded: {e:#}");
    }
    if let Err(e) = ThemeRegistry::global_mut(cx).load_themes_from_str(THEMES) {
        log::warn!("theme not loaded: {e:#}");
        return;
    }
    let themes = ThemeRegistry::global(cx).themes();
    let light = themes.get(&SharedString::from(LIGHT)).cloned();
    let dark = themes.get(&SharedString::from(DARK)).cloned();
    let theme = Theme::global_mut(cx);
    if let Some(light) = light {
        theme.light_theme = light;
    }
    if let Some(dark) = dark {
        theme.dark_theme = dark;
    }
}

/// Text in the preset's heading face.
pub fn heading(text: impl Into<SharedString>) -> Div {
    div().font_family(HEADING_FONT).font_weight(FontWeight::MEDIUM).child(text.into())
}

/// shadcn's radius steps around the theme's `md` radius, which buttons and
/// inputs use: `sm` for key caps, `lg` for the tab track.
pub fn radius_sm(theme: &Theme) -> Pixels {
    theme.radius * 0.75
}

pub fn radius_lg(theme: &Theme) -> Pixels {
    theme.radius * 1.25
}

/// A small tinted pill, like a shadcn badge.
pub fn badge(text: &'static str, color: gpui::Hsla, dark: bool) -> Div {
    div()
        .px_1p5()
        .h(px(16.))
        .flex()
        .items_center()
        .rounded_full()
        .bg(color.opacity(if dark { 0.2 } else { 0.1 }))
        .text_color(color)
        .font_weight(FontWeight::MEDIUM)
        .child(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_component::{ThemeMode, ThemeSet};

    #[test]
    fn the_theme_file_has_a_light_and_a_dark_theme() {
        let set: ThemeSet = serde_json::from_str(THEMES).unwrap();
        let modes: Vec<_> = set.themes.iter().map(|t| (t.name.to_string(), t.mode)).collect();
        assert!(modes.contains(&(LIGHT.into(), ThemeMode::Light)));
        assert!(modes.contains(&(DARK.into(), ThemeMode::Dark)));
    }

    #[test]
    fn every_colour_parses() {
        let raw: serde_json::Value = serde_json::from_str(THEMES).unwrap();
        for theme in raw["themes"].as_array().unwrap() {
            for (key, value) in theme["colors"].as_object().unwrap() {
                let value = value.as_str().unwrap();
                assert!(gpui_component::try_parse_color(value).is_ok(), "{key}: {value}");
            }
        }
    }

    #[test]
    fn the_embedded_fonts_are_the_families_the_theme_names() {
        let raw: serde_json::Value = serde_json::from_str(THEMES).unwrap();
        assert_eq!(raw["themes"][0]["font.family"], "Inter");
        // The OpenType name table carries the family name in UTF-16BE.
        let utf16 = |s: &str| s.encode_utf16().flat_map(u16::to_be_bytes).collect::<Vec<u8>>();
        let has = |font: &[u8], name: &str| {
            let needle = utf16(name);
            font.windows(needle.len()).any(|w| w == needle.as_slice())
        };
        assert!(has(FONTS[0], "Inter") && has(FONTS[1], "Inter"));
        assert!(has(FONTS[2], HEADING_FONT));
    }
}
