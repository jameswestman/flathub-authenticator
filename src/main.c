/* main.c
 *
 * Copyright 2022 James Westman
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <glib/gi18n.h>
#include <libsoup/soup.h>

#include "flathub_authenticator-config.h"
#include "org.freedesktop.Flatpak.Authenticator.h"
#include "org.freedesktop.Application.h"


static GDBusObjectManagerServer *manager = NULL;
static int active_requests = 0;


typedef struct {
  SoupServer *return_server;
  FlatpakAuthenticatorRequest *request_impl;
  GStrv refs;
} ActiveRequest;


static void
active_request_free (ActiveRequest *req)
{
  g_clear_object (&req->request_impl);
  g_clear_object (&req->return_server);
  g_clear_pointer (&req->refs, g_strfreev);
  g_free (req);
  active_requests --;
}


static void
on_request_finished (G_GNUC_UNUSED SoupServer        *server,
                     G_GNUC_UNUSED SoupMessage       *msg,
                     G_GNUC_UNUSED SoupClientContext *client,
                     gpointer                         user_data)
{
  ActiveRequest *req = (ActiveRequest *)user_data;

  g_debug ("Request finished");
  active_request_free (req);
}


static void
handle_return_request (G_GNUC_UNUSED SoupServer        *server,
                       SoupMessage                     *msg,
                       G_GNUC_UNUSED const char        *path,
                       GHashTable                      *query,
                       G_GNUC_UNUSED SoupClientContext *client,
                       gpointer                         user_data)
{
  ActiveRequest *req = (ActiveRequest *)user_data;
  SoupMessageHeaders *headers;
  GVariant *result = NULL;
  char *token;

  flatpak_authenticator_request_emit_webflow_done (req->request_impl, g_variant_new ("a{sv}", NULL));

  g_object_get (msg, "response-headers", &headers, NULL);
  soup_message_headers_replace (headers, "Access-Control-Allow-Origin", FRONTEND_URL);

  if (query == NULL || !g_hash_table_contains (query, "token"))
    {
      g_debug ("return request did not contain token");
      result = g_variant_new_parsed ("{'error-message': <'%s'>}", "server did not respond with token");
      flatpak_authenticator_request_emit_response (req->request_impl, 2, result);

      soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
      soup_message_set_response (msg, NULL, SOUP_MEMORY_STATIC, NULL, 0);

      return;
    }

  token = g_hash_table_lookup (query, "token");
  g_debug ("Received download token: %s", token);
  result = g_variant_new_parsed ("{'tokens': <{%s: %^as}>}", token, req->refs);
  flatpak_authenticator_request_emit_response (req->request_impl, 0, result);

  soup_message_set_status (msg, SOUP_STATUS_OK);
  soup_message_set_response (msg, NULL, SOUP_MEMORY_STATIC, NULL, 0);
}


static gboolean
handle_close (FlatpakAuthenticator  *authenticator,
              GDBusMethodInvocation *invocation,
              gpointer               user_data)
{
  ActiveRequest *req = (ActiveRequest *)user_data;

  g_assert (IS_FLATPAK_AUTHENTICATOR (authenticator));
  g_assert (G_IS_DBUS_METHOD_INVOCATION (invocation));

  active_request_free (req);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}


static gboolean
handle_request_ref_token (FlatpakAuthenticator     *authenticator,
                          GDBusMethodInvocation    *invocation,
                          G_GNUC_UNUSED const char *handle_token,
                          G_GNUC_UNUSED GVariant   *authenticator_options,
                          G_GNUC_UNUSED const char *remote,
                          G_GNUC_UNUSED const char *remote_uri,
                          GVariant                 *refs,
                          G_GNUC_UNUSED GVariant   *options,
                          G_GNUC_UNUSED const char *parent_window,
                          G_GNUC_UNUSED gpointer    user_data)
{
  g_autoptr(GStrvBuilder) ref_name_builder = g_strv_builder_new ();
  g_auto(GStrv) ref_names = NULL;
  g_autoptr(GDBusObjectSkeleton) object = NULL;
  g_autoptr(FlatpakAuthenticatorRequest) impl = NULL;
  g_autofree char *obj_path = NULL;
  g_autofree char *sender = NULL;
  g_autofree char *ref_string = NULL;
  g_autofree char *url = NULL;
  g_autofree char *return_uri = NULL;
  g_autoptr(GError) error = NULL;
  g_autoslist(SoupURI) uris = NULL;
  ActiveRequest *request;

  GVariant *result = NULL;
  GVariantIter iter;
  gchar *ref;

  g_assert (IS_FLATPAK_AUTHENTICATOR (authenticator));
  g_assert (G_IS_DBUS_METHOD_INVOCATION (invocation));

  /* Get list of flatpak refs from the D-Bus call */
  g_variant_iter_init (&iter, refs);
  while (g_variant_iter_loop (&iter, "(ssia{sv})", &ref, NULL, NULL, NULL))
    g_strv_builder_add (ref_name_builder, ref);

  ref_names = g_strv_builder_end (ref_name_builder);
  ref_string = g_strjoinv (";", ref_names);

  /* Create the request object */
  sender = g_strdup (g_dbus_method_invocation_get_sender (invocation));
  sender = g_strdelimit (sender, ".", '_');
  obj_path = g_strdup_printf ("/org/freedesktop/Flatpak/Authenticator/request/%s/%s", &sender[1], handle_token);
  object = g_dbus_object_skeleton_new (obj_path);

  impl = flatpak_authenticator_request_skeleton_new ();
  g_dbus_object_skeleton_add_interface (object, G_DBUS_INTERFACE_SKELETON (impl));

  g_dbus_object_manager_server_export (manager, object);

  /* Create a web server to listen for the end of the webflow */
  request = g_new0 (ActiveRequest, 1);
  request->return_server = soup_server_new (NULL, NULL);
  request->request_impl = g_object_ref (impl);
  request->refs = g_strdupv (ref_names);

  g_signal_connect (impl, "handle-close", G_CALLBACK (handle_close), request);

  soup_server_listen_local (request->return_server, 0, 0, &error);
  if (error != NULL)
    {
      g_prefix_error (&error, "could not listen for webflow response");
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  soup_server_add_handler (request->return_server, "/success", handle_return_request, request, NULL);

  /* When all requests are finished, free the request info. We can't do this in
   * handle_return_request because that would interrupt the ongoing HTTP response. */
  g_signal_connect (request->return_server, "request-finished", G_CALLBACK (on_request_finished), request);
  g_signal_connect (request->return_server, "request-aborted", G_CALLBACK (on_request_finished), request);

  uris = soup_server_get_uris (request->return_server);
  g_assert (g_slist_length (uris) > 0);
  return_uri = soup_uri_to_string ((SoupURI *)g_slist_nth_data (uris, 0), FALSE);

  /* Emit the Webflow signal */
  url = g_strdup_printf (FRONTEND_URL "/purchase?refs=%s&return=%ssuccess", ref_string, return_uri);
  g_debug ("Redirecting to %s", url);
  flatpak_authenticator_request_emit_webflow (impl, url, g_variant_new ("a{sv}", NULL));

  /* Return the path of the request object */
  result = g_variant_new_parsed ("(%o,)", obj_path);
  g_dbus_method_invocation_return_value (invocation, result);

  active_requests ++;

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}


static void
on_bus_acquired (GDBusConnection        *connection,
                 const char             *name,
                 G_GNUC_UNUSED gpointer  user_data)
{
  g_autoptr(GDBusObjectSkeleton) app = NULL;
  g_autoptr(Application) app_impl = NULL;
  g_autoptr(GDBusObjectSkeleton) object = NULL;
  g_autoptr(FlatpakAuthenticator) impl = NULL;

  g_assert (G_IS_DBUS_CONNECTION (connection));

  g_debug ("Bus acquired: %s", name);

  g_assert (manager == NULL);
  manager = g_dbus_object_manager_server_new ("/");

  object = g_dbus_object_skeleton_new ("/org/freedesktop/Flatpak/Authenticator");
  impl = flatpak_authenticator_skeleton_new ();
  flatpak_authenticator_set_version (impl, 1);
  g_signal_connect (impl, "handle-request-ref-tokens", G_CALLBACK (handle_request_ref_token), NULL);
  g_dbus_object_skeleton_add_interface (object, G_DBUS_INTERFACE_SKELETON (impl));
  g_dbus_object_manager_server_export (manager, object);

  app = g_dbus_object_skeleton_new ("/org/flathub/Authenticator");
  app_impl = application_skeleton_new ();
  g_dbus_object_skeleton_add_interface (app, G_DBUS_INTERFACE_SKELETON (app_impl));
  g_dbus_object_manager_server_export (manager, app);

  g_dbus_object_manager_server_set_connection (manager, connection);
}


static void
on_name_acquired (GDBusConnection        *connection,
                  const char             *name,
                  G_GNUC_UNUSED gpointer  user_data)
{
  g_assert (G_IS_DBUS_CONNECTION (connection));

  g_debug ("Acquired name: %s", name);
}


static void
on_name_lost (GDBusConnection        *connection,
              const char             *name,
              G_GNUC_UNUSED gpointer  user_data)
{
  g_assert (G_IS_DBUS_CONNECTION (connection));

  g_debug ("Lost name: %s", name);
}


static gboolean
quit_timer (GMainLoop *loop)
{
  g_assert (active_requests >= 0);

  if (active_requests == 0)
    {
      g_main_loop_quit (loop);
      g_debug ("Shutting down due to inactivity");
    }

  return G_SOURCE_CONTINUE;
}


int
main (void)
{
  g_autoptr(GMainLoop) loop = NULL;
  guint id;

  loop = g_main_loop_new (NULL, FALSE);
  g_timeout_add_seconds (60, G_SOURCE_FUNC (quit_timer), loop);

  id = g_bus_own_name (G_BUS_TYPE_SESSION,
                       "org.flathub.Authenticator",
                       G_BUS_NAME_OWNER_FLAGS_NONE,
                       on_bus_acquired,
                       on_name_acquired,
                       on_name_lost,
                       NULL,
                       NULL);

  g_main_loop_run (loop);

  g_bus_unown_name (id);

  return 0;
}
