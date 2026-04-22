//go:build gui

package gui

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"image/color"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/tokoko/oidc-init/internal/auth"
	"github.com/tokoko/oidc-init/internal/deviceflow"
	"github.com/tokoko/oidc-init/internal/profiles"
	"github.com/tokoko/oidc-init/internal/storage"
)

var (
	// Semantic status colors (used for pill text + tinted background;
	// kept opaque so they read on both light and dark variants).
	colorValid   = color.NRGBA{R: 0x16, G: 0xa3, B: 0x4a, A: 0xff}
	colorWarn    = color.NRGBA{R: 0xea, G: 0x9a, B: 0x14, A: 0xff}
	colorExpired = color.NRGBA{R: 0xdc, G: 0x26, B: 0x26, A: 0xff}
	colorMuted   = color.NRGBA{R: 0x71, G: 0x71, B: 0x7a, A: 0xff}
)

// Run launches the desktop GUI window and blocks until it is closed.
func Run() {
	a := app.NewWithID("com.github.tokoko.oidc-init")
	a.Settings().SetTheme(appTheme{})
	a.SetIcon(logoResource)
	w := a.NewWindow("oidc-init")
	w.SetIcon(logoResource)
	w.Resize(fyne.NewSize(760, 560))

	ui := &ui{app: a, window: w}
	w.SetContent(ui.build())
	ui.populate()

	w.ShowAndRun()
}

type ui struct {
	app    fyne.App
	window fyne.Window

	cards  *fyne.Container
	scroll *container.Scroll
	status *widget.Label
	count  *widget.Label
}

func (u *ui) build() fyne.CanvasObject {
	u.cards = container.NewVBox()
	u.scroll = container.NewVScroll(u.cards)
	u.status = widget.NewLabel("")
	u.count = widget.NewLabel("")
	u.count.Alignment = fyne.TextAlignTrailing

	title := canvas.NewText("oidc-init", accentColor(u.app))
	title.TextSize = 22
	title.TextStyle = fyne.TextStyle{Bold: true}

	subtitle := canvas.NewText("OIDC token manager", mutedColor(u.app))
	subtitle.TextSize = 12

	logo := canvas.NewImageFromResource(logoResource)
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(40, 40))

	titleText := container.NewVBox(title, subtitle)
	titleBox := container.NewHBox(logo, titleText)

	toolbar := widget.NewToolbar(
		widget.NewToolbarSpacer(),
		widget.NewToolbarAction(theme.ContentAddIcon(), func() { u.editProfile("", nil) }),
		widget.NewToolbarAction(theme.ViewRefreshIcon(), func() { u.populate() }),
		widget.NewToolbarAction(theme.DeleteIcon(), func() { u.confirmPurgeAll() }),
	)

	header := container.NewBorder(nil, nil, titleBox, toolbar)
	headerPad := container.NewPadded(header)

	footer := container.NewBorder(nil, nil, u.status, u.count)
	footerPad := container.NewPadded(footer)

	body := container.NewPadded(u.scroll)

	return container.NewBorder(headerPad, footerPad, nil, nil, body)
}

func (u *ui) populate() {
	u.cards.RemoveAll()

	mgr, err := profiles.NewManager()
	if err != nil {
		u.cards.Add(u.errorCard(err))
		u.cards.Refresh()
		return
	}
	names, err := mgr.List()
	if err != nil {
		u.cards.Add(u.errorCard(err))
		u.cards.Refresh()
		return
	}
	if len(names) == 0 {
		u.cards.Add(u.emptyState())
		u.cards.Refresh()
		u.count.SetText("")
		u.status.SetText("")
		return
	}

	def, _ := mgr.GetDefault()
	for _, name := range names {
		u.cards.Add(u.profileCard(mgr, name, name == def))
	}
	u.cards.Refresh()
	u.count.SetText(fmt.Sprintf("%d profile(s)", len(names)))
}

func (u *ui) emptyState() fyne.CanvasObject {
	icon := widget.NewIcon(theme.AccountIcon())
	headline := canvas.NewText("No profiles yet", fgColor(u.app))
	headline.TextSize = 16
	headline.TextStyle = fyne.TextStyle{Bold: true}
	headline.Alignment = fyne.TextAlignCenter

	hint := widget.NewLabel("Create one from the CLI:\n  oidc init --save-profile <name> --endpoint <url> --realm <realm> --client-id <id>")
	hint.Alignment = fyne.TextAlignCenter

	return container.NewPadded(container.NewVBox(
		container.NewCenter(icon),
		headline,
		hint,
	))
}

func (u *ui) errorCard(err error) fyne.CanvasObject {
	t := canvas.NewText("Error: "+err.Error(), colorExpired)
	t.TextSize = 13
	return container.NewPadded(t)
}

func (u *ui) profileCard(mgr *profiles.Manager, name string, isDefault bool) fyne.CanvasObject {
	p, err := mgr.Get(name)
	if err != nil {
		return u.errorCard(fmt.Errorf("%s: %w", name, err))
	}
	key := storage.GenerateStorageKey(p.Endpoint, p.Realm, p.ClientID, name)

	statusText, statusColor := tokenStatus(key)

	nameText := name
	if isDefault {
		nameText = name + "  ★"
	}

	subtitleText := canvas.NewText(
		fmt.Sprintf("%s · %s · %s", trimURL(p.Endpoint), p.Realm, p.ClientID),
		mutedColor(u.app),
	)
	subtitleText.TextSize = 12

	pill := statusPill(statusText, statusColor)

	authBtn := widget.NewButtonWithIcon("Authenticate", theme.LoginIcon(), func() {
		u.authenticate(name, p, key)
	})
	authBtn.Importance = widget.HighImportance

	showBtn := widget.NewButtonWithIcon("Token", theme.VisibilityIcon(), func() {
		u.showToken(key)
	})
	editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
		u.editProfile(name, p)
	})
	purgeBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
		u.confirmPurge(key)
	})

	if !storage.TokenExists(key) {
		showBtn.Disable()
		purgeBtn.Disable()
	}

	actions := container.NewHBox(authBtn, showBtn, editBtn, purgeBtn)

	row := container.NewBorder(nil, nil, pill, actions)
	body := container.NewVBox(subtitleText, row)
	card := widget.NewCard(nameText, "", body)
	return card
}

// statusPill draws a rounded, tinted badge with a colored label inside.
func statusPill(text string, c color.Color) fyne.CanvasObject {
	r, g, b, _ := c.RGBA()
	bg := color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: 0x28}

	rect := canvas.NewRectangle(bg)
	rect.CornerRadius = 10
	rect.StrokeWidth = 0

	label := canvas.NewText(text, c)
	label.TextSize = 11
	label.TextStyle = fyne.TextStyle{Bold: true}

	padded := container.New(&padLayout{padX: 10, padY: 4}, label)
	return container.NewStack(rect, padded)
}

// padLayout adds horizontal/vertical padding around a single child.
type padLayout struct{ padX, padY float32 }

func (p *padLayout) MinSize(objs []fyne.CanvasObject) fyne.Size {
	if len(objs) == 0 {
		return fyne.NewSize(0, 0)
	}
	m := objs[0].MinSize()
	return fyne.NewSize(m.Width+2*p.padX, m.Height+2*p.padY)
}
func (p *padLayout) Layout(objs []fyne.CanvasObject, sz fyne.Size) {
	if len(objs) == 0 {
		return
	}
	objs[0].Move(fyne.NewPos(p.padX, p.padY))
	objs[0].Resize(fyne.NewSize(sz.Width-2*p.padX, sz.Height-2*p.padY))
}

func tokenStatus(key string) (string, color.Color) {
	if !storage.TokenExists(key) {
		return "no token", colorMuted
	}
	data, err := storage.GetTokens(key)
	if err != nil {
		return "error", colorExpired
	}
	expiresAt, err := time.Parse(time.RFC3339, data.ExpiresAt)
	if err != nil {
		return "expires_at unparseable", colorExpired
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return "expired", colorExpired
	}
	if remaining < 5*time.Minute {
		return "expires in " + humanDuration(remaining), colorWarn
	}
	return "valid · " + humanDuration(remaining), colorValid
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func trimURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Host
	}
	return s
}

func (u *ui) authenticate(name string, p *profiles.Profile, key string) {
	if p.Flow != "" && p.Flow != "device" {
		dialog.ShowError(fmt.Errorf("only device flow is supported in the GUI; profile %q uses %q", name, p.Flow), u.window)
		return
	}

	protocol := p.Protocol
	if protocol == "" {
		protocol = "https"
	}
	scope := p.Scope
	if scope == "" {
		scope = "openid profile email"
	}

	httpClient := &http.Client{}
	if !p.Verify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	cfg := &deviceflow.Config{
		TokenEndpoint: auth.BuildTokenEndpoint(p.Endpoint, p.Realm, protocol),
		ClientID:      p.ClientID,
		ClientSecret:  p.ClientSecret,
		Scope:         scope,
		HTTPClient:    httpClient,
	}

	u.status.SetText("Requesting device code for " + name + "...")

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		dar, err := deviceflow.RequestDeviceCode(ctx, cfg)
		if err != nil {
			cancel()
			fyne.Do(func() {
				u.status.SetText("")
				dialog.ShowError(err, u.window)
			})
			return
		}

		fyne.Do(func() {
			u.showDeviceCodeDialog(ctx, cancel, name, key, cfg, dar)
		})
	}()
}

func (u *ui) showDeviceCodeDialog(ctx context.Context, cancel context.CancelFunc, name, key string, cfg *deviceflow.Config, dar *deviceflow.DeviceAuthResponse) {
	browseURL := dar.VerificationURIComplete
	if browseURL == "" {
		browseURL = dar.VerificationURI
	}

	codeText := canvas.NewText(dar.UserCode, theme.Color(theme.ColorNamePrimary))
	codeText.TextSize = 32
	codeText.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	codeText.Alignment = fyne.TextAlignCenter

	codeBox := container.NewPadded(codeText)

	urlLbl := widget.NewLabel(dar.VerificationURI)
	urlLbl.Wrapping = fyne.TextWrapBreak
	urlLbl.Alignment = fyne.TextAlignCenter

	openBtn := widget.NewButtonWithIcon("Open in browser", theme.ComputerIcon(), func() {
		if err := openBrowser(browseURL); err != nil {
			dialog.ShowError(err, u.window)
		}
	})
	openBtn.Importance = widget.HighImportance

	progress := widget.NewProgressBarInfinite()
	waitingLbl := canvas.NewText("Waiting for authorization...", mutedColor(u.app))
	waitingLbl.TextSize = 12
	waitingLbl.Alignment = fyne.TextAlignCenter

	step1 := widget.NewLabelWithStyle("1. Visit this URL", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	step2 := widget.NewLabelWithStyle("2. Enter the code", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	content := container.NewVBox(
		step1,
		urlLbl,
		container.NewCenter(openBtn),
		widget.NewSeparator(),
		step2,
		codeBox,
		widget.NewSeparator(),
		waitingLbl,
		progress,
	)

	d := dialog.NewCustom("Authenticate "+name, "Cancel", container.NewPadded(content), u.window)
	d.Resize(fyne.NewSize(480, 440))
	d.SetOnClosed(func() {
		cancel()
	})
	d.Show()

	// Auto-open the verification URL — the button stays as a fallback if this fails.
	go func() {
		if err := openBrowser(browseURL); err != nil {
			fyne.Do(func() {
				u.status.SetText("Could not open browser automatically — click 'Open in browser'")
			})
		}
	}()

	go func() {
		tokenResp, err := deviceflow.PollForToken(ctx, cfg, dar.DeviceCode, dar.ExpiresIn, dar.Interval)
		if err != nil {
			fyne.Do(func() {
				d.Hide()
				u.status.SetText("")
				if errors.Is(err, context.Canceled) {
					return
				}
				dialog.ShowError(err, u.window)
			})
			return
		}
		saveErr := storage.SaveTokens(key, &storage.TokenResponse{
			AccessToken:  tokenResp.AccessToken,
			TokenType:    tokenResp.TokenType,
			ExpiresIn:    tokenResp.ExpiresIn,
			RefreshToken: tokenResp.RefreshToken,
			Scope:        tokenResp.Scope,
			IDToken:      tokenResp.IDToken,
		})
		fyne.Do(func() {
			d.Hide()
			if saveErr != nil {
				dialog.ShowError(saveErr, u.window)
				return
			}
			u.status.SetText("✓ Tokens saved for " + name)
			u.populate()
		})
	}()
}

func (u *ui) showToken(key string) {
	data, err := storage.GetTokens(key)
	if err != nil {
		dialog.ShowError(err, u.window)
		return
	}
	entry := widget.NewMultiLineEntry()
	entry.SetText(data.AccessToken)
	entry.Wrapping = fyne.TextWrapBreak
	entry.TextStyle = fyne.TextStyle{Monospace: true}

	metaForm := widget.NewForm(
		widget.NewFormItem("Type", widget.NewLabel(data.TokenType)),
		widget.NewFormItem("Issued", widget.NewLabel(data.IssuedAt)),
		widget.NewFormItem("Expires", widget.NewLabel(data.ExpiresAt)),
		widget.NewFormItem("Scope", widget.NewLabel(data.Scope)),
	)

	copyBtn := widget.NewButtonWithIcon("Copy access token", theme.ContentCopyIcon(), func() {
		u.window.Clipboard().SetContent(data.AccessToken)
		u.status.SetText("✓ Token copied to clipboard")
	})

	top := container.NewVBox(metaForm, copyBtn, widget.NewSeparator())
	content := container.NewBorder(top, nil, nil, nil, entry)
	d := dialog.NewCustom("Token: "+key, "Close", content, u.window)
	d.Resize(fyne.NewSize(620, 460))
	d.Show()
}

func (u *ui) confirmPurge(key string) {
	dialog.ShowConfirm("Purge token", "Delete stored tokens for "+key+"?", func(ok bool) {
		if !ok {
			return
		}
		if err := storage.DeleteTokens(key); err != nil {
			dialog.ShowError(err, u.window)
			return
		}
		u.status.SetText("Deleted tokens for " + key)
		u.populate()
	}, u.window)
}

func (u *ui) confirmPurgeAll() {
	dialog.ShowConfirm("Purge all tokens", "Delete every stored token?", func(ok bool) {
		if !ok {
			return
		}
		if err := storage.PurgeAll(); err != nil {
			dialog.ShowError(err, u.window)
			return
		}
		u.status.SetText("All tokens purged")
		u.populate()
	}, u.window)
}

// editProfile opens a form to create (existing == nil) or edit a profile.
func (u *ui) editProfile(originalName string, existing *profiles.Profile) {
	mgr, err := profiles.NewManager()
	if err != nil {
		dialog.ShowError(err, u.window)
		return
	}

	creating := existing == nil
	if creating {
		existing = &profiles.Profile{
			Protocol: "https",
			Flow:     "device",
			Scope:    "openid profile email",
			Verify:   true,
		}
	}

	nameEntry := widget.NewEntry()
	nameEntry.SetText(originalName)
	if !creating {
		nameEntry.Disable()
	}

	endpointEntry := widget.NewEntry()
	endpointEntry.SetText(existing.Endpoint)
	endpointEntry.SetPlaceHolder("auth.example.com")

	realmEntry := widget.NewEntry()
	realmEntry.SetText(existing.Realm)

	clientIDEntry := widget.NewEntry()
	clientIDEntry.SetText(existing.ClientID)

	clientSecretEntry := widget.NewPasswordEntry()
	clientSecretEntry.SetText(existing.ClientSecret)

	scopeEntry := widget.NewEntry()
	scopeEntry.SetText(existing.Scope)

	protocolSel := widget.NewSelect([]string{"https", "http"}, nil)
	protocolSel.SetSelected(existing.Protocol)

	flowSel := widget.NewSelect([]string{"device", "password"}, nil)
	flowSel.SetSelected(existing.Flow)

	verifyCheck := widget.NewCheck("Verify TLS certificate", nil)
	verifyCheck.SetChecked(existing.Verify)

	usernameEntry := widget.NewEntry()
	usernameEntry.SetText(existing.Username)

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Name", Widget: nameEntry, HintText: "Profile identifier"},
			{Text: "Endpoint", Widget: endpointEntry},
			{Text: "Realm", Widget: realmEntry},
			{Text: "Client ID", Widget: clientIDEntry},
			{Text: "Client secret", Widget: clientSecretEntry, HintText: "Optional"},
			{Text: "Scope", Widget: scopeEntry},
			{Text: "Protocol", Widget: protocolSel},
			{Text: "Flow", Widget: flowSel},
			{Text: "Username", Widget: usernameEntry, HintText: "Required for password flow"},
			{Text: "", Widget: verifyCheck},
		},
	}

	title := "New profile"
	if !creating {
		title = "Edit profile: " + originalName
	}

	d := dialog.NewCustomConfirm(title, "Save", "Cancel", form, func(ok bool) {
		if !ok {
			return
		}
		name := nameEntry.Text
		if name == "" {
			dialog.ShowError(fmt.Errorf("name is required"), u.window)
			return
		}
		if endpointEntry.Text == "" || realmEntry.Text == "" || clientIDEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("endpoint, realm, and client ID are required"), u.window)
			return
		}
		p := &profiles.Profile{
			Endpoint:     endpointEntry.Text,
			Realm:        realmEntry.Text,
			ClientID:     clientIDEntry.Text,
			ClientSecret: clientSecretEntry.Text,
			Scope:        scopeEntry.Text,
			Protocol:     protocolSel.Selected,
			Flow:         flowSel.Selected,
			Verify:       verifyCheck.Checked,
			Username:     usernameEntry.Text,
		}
		if err := mgr.Add(name, p, !creating); err != nil {
			dialog.ShowError(err, u.window)
			return
		}
		if creating {
			u.status.SetText("✓ Profile " + name + " created")
		} else {
			u.status.SetText("✓ Profile " + name + " updated")
		}
		u.populate()
	}, u.window)
	d.Resize(fyne.NewSize(520, 520))
	d.Show()
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
