//! Icon SVGs: gpui-component's default set plus the few it lacks.

use std::borrow::Cow;

use gpui::{AssetSource, Result, SharedString};

gpui_kit_assets::icon_assets!(Extra, [Lock, Trash]);

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = Extra.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit_assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit_assets::Assets.list(path)?;
        paths.extend(Extra.list(path)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_component::IconName;
    use gpui_kit_assets::IconNamed;

    #[test]
    fn every_row_icon_loads() {
        let paths = [
            IconName::Copy.path(),
            IconName::Star.path(),
            IconName::StarFill.path(),
            gpui_kit_assets::IconName::Lock.path(),
            gpui_kit_assets::IconName::Trash.path(),
        ];
        for path in paths {
            let svg = Assets.load(&path).unwrap();
            assert!(svg.is_some_and(|b| b.starts_with(b"<svg")), "{path}");
        }
    }
}
