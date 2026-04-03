<?php

declare(strict_types=1);

class WebhookLibrary extends IPSModule
{
    public function Create()
    {
        // Never delete this line!
        parent::Create();

        // Properties
        $this->RegisterPropertyInteger('SecretsManagerID', 0);
    }

    public function Destroy()
    {
        // Never delete this line!
        parent::Destroy();
    }

    public function ApplyChanges()
    {
        // Never delete this line!
        parent::ApplyChanges();

        // Register the Webhook
        $this->RegisterHook('/hook/library');
    }

    protected function ProcessHookData()
    {
        // 1. Authentication (SecretsManager)
        $instanceID = $this->ReadPropertyInteger('SecretsManagerID');

        if ($instanceID > 0 && @IPS_InstanceExists($instanceID)) {
            if (function_exists('SEC_IsPortalAuthenticated')) {
                if (!SEC_IsPortalAuthenticated($instanceID)) {
                    $currentUrl = $_SERVER['REQUEST_URI'] ?? '';
                    $loginUrl = "/hook/secrets_" . (string)$instanceID . "?portal=1&return=" . urlencode($currentUrl);
                    header('Location: ' . $loginUrl);
                    return;
                }
            }
        }

        // 2. Retrieve WebHook Control instance
        $ids = IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');
        if (count($ids) === 0) {
            echo 'Error: WebHook Control instance not found.';
            return;
        }

        $webHookControlID = $ids[0];

        // 3. Read complete configuration so we can also detect internal hooks
        $configRaw = IPS_GetConfiguration($webHookControlID);
        $config = json_decode($configRaw, true);

        if (!is_array($config)) {
            echo 'Error: Could not read WebHook Control configuration.';
            return;
        }

        $userHooks = [];
        $internalHooks = [];

        foreach ($config as $propertyName => $propertyValue) {
            if (!is_array($propertyValue)) {
                continue;
            }

            foreach ($propertyValue as $row) {
                if (!is_array($row)) {
                    continue;
                }

                if (!isset($row['Hook']) || !is_string($row['Hook'])) {
                    continue;
                }

                $hook = trim($row['Hook']);
                if ($hook === '') {
                    continue;
                }

                $url = (strpos($hook, '/') === 0) ? $hook : '/hook/' . ltrim($hook, '/');

                $entry = [
                    'url'   => $url,
                    'hook'  => $hook,
                    'row'   => $row,
                    'source' => (string)$propertyName
                ];

                if (stripos((string)$propertyName, 'internal') !== false) {
                    $internalHooks[$url] = $entry;
                } else {
                    $userHooks[$url] = $entry;
                }
            }
        }

        ksort($userHooks, SORT_NATURAL | SORT_FLAG_CASE);
        ksort($internalHooks, SORT_NATURAL | SORT_FLAG_CASE);

        // 4. Generate HTML
        $html = "<!DOCTYPE html><html><head><title>Webhook Library</title>";
        $html .= "<meta name='viewport' content='width=device-width, initial-scale=1'>";
        $html .= "<style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background-color: #f4f4f9; }
                h2, h3 { color: #333; }
                ul { list-style-type: none; padding: 0; }
                li { background: #fff; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; transition: background 0.2s; }
                li:hover { background: #e9ecef; }
                a { display: block; padding: 15px 15px 4px 15px; text-decoration: none; color: #0078d7; font-weight: bold; }
                .sub { display: block; padding: 0 15px 15px 15px; color: #666; font-size: 12px; font-weight: normal; }
                .empty { color: #666; font-style: italic; margin-bottom: 20px; }
              </style>";
        $html .= "</head><body>";
        $html .= "<h2>Available Links</h2>";

        // Internal hooks
        $html .= "<h3>Internal WebHooks</h3>";
        if (count($internalHooks) === 0) {
            $html .= "<div class='empty'>No internal hooks found.</div>";
        } else {
            $html .= "<ul>";
            foreach ($internalHooks as $entry) {
                $escapedUrl = htmlspecialchars($entry['url'], ENT_QUOTES, 'UTF-8');

                $label = $entry['url'];
                if (isset($entry['row']['InstanceID']) && @IPS_ObjectExists((int)$entry['row']['InstanceID'])) {
                    $label = IPS_GetName((int)$entry['row']['InstanceID']) . ' - ' . $entry['url'];
                }

                $escapedLabel = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');

                $html .= "<li>";
                $html .= "<a href=\"" . $escapedUrl . "\" target=\"_blank\" rel=\"noopener noreferrer\">" . $escapedLabel . "</a>";
                $html .= "<span class='sub'>" . $escapedUrl . "</span>";
                $html .= "</li>";
            }
            $html .= "</ul>";
        }

        // User hooks
        $html .= "<h3>Registered WebHooks</h3>";
        if (count($userHooks) === 0) {
            $html .= "<div class='empty'>No registered webhooks found.</div>";
        } else {
            $html .= "<ul>";
            foreach ($userHooks as $entry) {
                $escapedUrl = htmlspecialchars($entry['url'], ENT_QUOTES, 'UTF-8');
                $html .= "<li><a href=\"" . $escapedUrl . "\" target=\"_blank\" rel=\"noopener noreferrer\">" . $escapedUrl . "</a></li>";
            }
            $html .= "</ul>";
        }

        $html .= "</body></html>";

        echo $html;
    }

    private function RegisterHook($WebHook)
    {
        // Correct GUID for your system
        $ids = IPS_GetInstanceListByModuleID("{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}");

        // REMOVED: Auto-creation logic (Guideline 2.iv violation)

        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], "Hooks"), true);
            $found = false;

            if (!is_array($hooks)) {
                $hooks = [];
                $this->LogMessage("Webhook list was empty/invalid. Creating new list.", KL_MESSAGE);
            }

            foreach ($hooks as $index => $hook) {
                if ($hook['Hook'] == $WebHook) {
                    if ($hook['TargetID'] == $this->InstanceID) {
                        return;
                    }
                    $hooks[$index]['TargetID'] = $this->InstanceID;
                    $found = true;
                    $this->LogMessage("Webhook '$WebHook' was taken over by this instance.", KL_MESSAGE);
                }
            }
            if (!$found) {
                $hooks[] = ["Hook" => $WebHook, "TargetID" => $this->InstanceID];
                $this->LogMessage("Webhook '$WebHook' was successfully created.", KL_MESSAGE);
            }
            IPS_SetProperty($ids[0], "Hooks", json_encode($hooks));
            IPS_ApplyChanges($ids[0]);
        } else {
            // Log error instead of creating instance
            $this->LogMessage("Error: WebHook Control Instance not found! Please check your Core Instances.", KL_ERROR);
        }
    }
}
