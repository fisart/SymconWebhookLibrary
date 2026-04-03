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
                    header("Location: " . $loginUrl);
                    return;
                }
            }
        }

        // 2. Collect registered webhooks
        $webhookLinks = [];
        $ids = IPS_GetInstanceListByModuleID("{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}");

        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], 'Hooks'), true);
            if (is_array($hooks)) {
                foreach ($hooks as $hook) {
                    if (!isset($hook['Hook']) || !is_string($hook['Hook'])) {
                        continue;
                    }

                    $url = trim($hook['Hook']);
                    if ($url === '') {
                        continue;
                    }

                    $webhookLinks[$url] = [
                        'url'   => $url,
                        'label' => $url
                    ];
                }
            }
        }

        ksort($webhookLinks, SORT_NATURAL | SORT_FLAG_CASE);

        // 3. Collect internal WebFront links
        // Symcon WebFronts can be addressed via /#<WebFrontID>
        $webfrontLinks = [];

        foreach (IPS_GetInstanceList() as $id) {
            $instance = @IPS_GetInstance($id);
            if (!is_array($instance) || !isset($instance['ModuleInfo']['ModuleName'])) {
                continue;
            }

            $moduleName = (string)$instance['ModuleInfo']['ModuleName'];

            // Detect WebFront-like modules
            if (stripos($moduleName, 'WebFront') === false) {
                continue;
            }

            $object = @IPS_GetObject($id);
            $name   = is_array($object) && isset($object['ObjectName']) && $object['ObjectName'] !== ''
                ? $object['ObjectName']
                : ('WebFront ' . $id);

            $url = '/#' . $id;

            $webfrontLinks[$url] = [
                'url'   => $url,
                'label' => $name . ' (#' . $id . ')'
            ];
        }

        ksort($webfrontLinks, SORT_NATURAL | SORT_FLAG_CASE);

        // 4. Generate HTML Output
        $html = "<!DOCTYPE html><html><head><title>Webhook Library</title>";
        $html .= "<meta name='viewport' content='width=device-width, initial-scale=1'>";
        $html .= "<style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background-color: #f4f4f9; }
                h2, h3 { color: #333; }
                ul { list-style-type: none; padding: 0; }
                li { background: #fff; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; transition: background 0.2s; }
                li:hover { background: #e9ecef; }
                a { display: block; padding: 15px; text-decoration: none; color: #0078d7; font-weight: bold; }
                .sub { display: block; padding: 0 15px 15px 15px; color: #666; font-size: 12px; font-weight: normal; }
                .empty { color: #666; font-style: italic; margin-bottom: 20px; }
              </style>";
        $html .= "</head><body>";
        $html .= "<h2>Available Links</h2>";

        // WebFront section
        $html .= "<h3>Internal WebFront Links</h3>";
        if (count($webfrontLinks) === 0) {
            $html .= "<div class='empty'>No WebFront instances found.</div>";
        } else {
            $html .= "<ul>";
            foreach ($webfrontLinks as $entry) {
                $escapedUrl   = htmlspecialchars($entry['url'], ENT_QUOTES, 'UTF-8');
                $escapedLabel = htmlspecialchars($entry['label'], ENT_QUOTES, 'UTF-8');
                $html .= "<li><a href=\"" . $escapedUrl . "\" target=\"_blank\" rel=\"noopener noreferrer\">" . $escapedLabel . "</a>";
                $html .= "<span class='sub'>" . $escapedUrl . "</span></li>";
            }
            $html .= "</ul>";
        }

        // WebHook section
        $html .= "<h3>Registered WebHooks</h3>";
        if (count($webhookLinks) === 0) {
            $html .= "<div class='empty'>No registered webhooks found.</div>";
        } else {
            $html .= "<ul>";
            foreach ($webhookLinks as $entry) {
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
