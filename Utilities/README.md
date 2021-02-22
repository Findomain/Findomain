# Kill Chromium/Chrome hanged instances

**Note:** this will kill all the Chrome/Chromium instances that have been running for more than 5 minutes which is an exaggerated time to take a screenshot but normal on your desktop PC. Therefore, this is intended to run on a machine where the only use of Chrome/Chromium is to take screenshots, for example, a VPS used for recon.

## Chromium
Put the `chromium-killer.service` and `chromium-killer.timer` files inside `/etc/systemd/system` and then run:

```bash
systemctl enable --now chromium-killer.timer
```

## Chrome

If you are using Chrome, follow the same steps but replace `/^chromium-*/` for `/^chrome*/` in the `chromium-killer.service` file.
