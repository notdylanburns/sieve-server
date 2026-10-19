use log::warn;
use sieve_common::{LogError, database::sites::Scheme};
use site_icons::{Icon as SiteIcon, IconInfo, SiteIcons};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum IconType {
    PNG((u32, u32)),
    SVG(Option<(u32, u32)>),
}

impl TryFrom<IconInfo> for IconType {
    type Error = ();

    fn try_from(value: IconInfo) -> Result<Self, Self::Error> {
        Ok(match value {
            IconInfo::PNG { size } => Self::PNG((size.width, size.height)),
            IconInfo::SVG { size } => Self::SVG(size.map(|size| (size.width, size.height))),
            _ => {
                return Err(());
            }
        })
    }
}

#[derive(Debug)]
pub(super) struct Icon {
    url: url::Url,
    icon_type: IconType,
}

impl TryFrom<SiteIcon> for Icon {
    type Error = ();

    fn try_from(value: SiteIcon) -> Result<Self, Self::Error> {
        Ok(Self {
            url: value.url,
            icon_type: value.info.try_into()?,
        })
    }
}
