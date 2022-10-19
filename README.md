# flathub-authenticator

This is the repository authenticator app for Flathub. When you download an app that requires payment or allows donations,
this "app" will be downloaded automatically. It directs you to the Flathub website, where you can pay for the app, and
then returns the download token to the flatpak client.

A token for your account is saved so that updates don't require you to log in again.

## Why the browser?

Stripe, the payment processor Flathub uses, has a web-based frontend for making purchases. Native user interfaces for
accepting payments would be very complicated--not every available payment method is as simple as entering a card number
and PIN.

More importantly, we want to be DE-agnostic. Making a different native frontend for every desktop--or even making an
API sufficient to handle payments so each desktop can provide their own--would not be scalable, so using the Flathub
website is the next best way.

## Repository Configuration

To configure the repository to use this app, it must first be uploaded as part of the repo. Then, run the following
command:

```sh
flatpak build-update-repo --authenticator-name=org.flathub.Authenticator --authenticator-install <repo path>
```

You can check the configuration with:

```sh
ostree summary -v <repo path>
```

It should contain the keys `xa.authenticator-name: 'org.flathub.Authenticator'` and `xa.authenticator-install: true`.

## Related Documentation

[org.freedesktop.Flatpak.Authenticator D-Bus API](https://docs.flatpak.org/en/latest/libflatpak-api-reference.html?highlight=authenticator#gdbus-org.freedesktop.Flatpak.Authenticator)