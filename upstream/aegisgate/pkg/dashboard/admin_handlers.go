// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package dashboard

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate/pkg/i18n"
	"log/slog"
)

type AdminHandler struct {
	authManager *auth.Manager
	dashboard   *Dashboard
}

func NewAdminHandler(authManager *auth.Manager, dashboard *Dashboard) *AdminHandler {
	return &AdminHandler{authManager: authManager, dashboard: dashboard}
}

func (ah *AdminHandler) RegisterRoutes() {
	slog.Debug("Admin routes registered")
}

// HandleLocale handles GET /api/locale
// Returns current locale and supported locales
func (d *Dashboard) HandleLocale(w http.ResponseWriter, r *http.Request) error {
	locale := d.getLocaleFromRequest(r)

	response := map[string]interface{}{
		"current_locale":    string(locale),
		"supported_locales": []map[string]string{},
	}

	if d.i18n != nil {
		for _, l := range i18n.SupportedLocales() {
			response["supported_locales"] = append(response["supported_locales"].([]map[string]string), map[string]string{
				"code":     string(l),
				"language": d.t(locale, "locale."+string(l)),
			})
		}
		response["default_locale"] = string(d.i18n.GetDefault())
	}

	d.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Data:      response,
		Timestamp: time.Now(),
	})
	return nil
}

// HandleSetLocale handles POST /api/locale
// Sets the current locale
func (d *Dashboard) HandleSetLocale(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		locale := d.getLocaleFromRequest(r)
		d.errorResponse(w, http.StatusMethodNotAllowed, d.t(locale, "error.method_not_allowed"))
		return nil
	}

	var req struct {
		Locale string `json:"locale"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		locale := d.getLocaleFromRequest(r)
		d.errorResponse(w, http.StatusBadRequest, d.tWith(locale, "error.invalid_request", map[string]interface{}{"Error": err.Error()}))
		return nil
	}

	newLocale := i18n.ParseLocale(req.Locale)
	if !i18n.IsValidLocale(newLocale) {
		locale := d.getLocaleFromRequest(r)
		d.errorResponse(w, http.StatusBadRequest, d.tWith(locale, "error.invalid_locale", map[string]interface{}{"Locale": req.Locale}))
		return nil
	}

	if err := d.SetLocale(newLocale); err != nil {
		locale := d.getLocaleFromRequest(r)
		d.errorResponse(w, http.StatusInternalServerError, d.tWith(locale, "error.internal", map[string]interface{}{"Error": err.Error()}))
		return nil
	}

	d.writeJSON(w, http.StatusOK, APIResponse{
		Success:   true,
		Data:      map[string]string{"locale": string(newLocale)},
		Timestamp: time.Now(),
	})
	return nil
}
