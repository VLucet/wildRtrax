#' Evaluate a classifier
#'
#' @description Calculates precision, recall, and F-score of BirdNET for a requested sequence of thresholds. You can request the metrics at the minute level for recordings that are processed with the species per minute method (1SPM). You can also exclude species that are not allowed in the project from the BirdNET results before evaluation.
#'
#' @param data Output from the `wt_download_report()` function when you request the `main` and `birdnet` reports
#' @param resolution Character; either "recording" to summarize at the entire recording level or "minute" to summarize the minute level if the `task_method` is "1SPM", or "task"
#' @param remove_species Logical; indicates whether species that are not allowed in the WildTrax project should be removed from the BirdNET report
#' @param species Character; optional subset of species to calculate metrics for (e.g., species = c("OVEN", "OSFL", "BOCH"))
#' @param thresholds Numeric; start and end of sequence of score thresholds at which to calculate performance metrics
#'
#' @import dplyr
#' @export
#'
#' @examples
#' \dontrun{
#' data <- wt_download_report(project_id = 1144, sensor_id = "ARU",
#' reports = c("main", "birdnet"), weather_cols = FALSE)
#'
#' eval <- wt_evaluate_classifier(data, resolution = "recording",
#' remove_species = TRUE, thresholds = c(10, 99))
#' }
#'
#' @return A tibble containing columns for precision, recall, and F-score for each of the requested thresholds.

wt_evaluate_classifier <- function(data, resolution = "recording", remove_species = TRUE,  species = NULL, thresholds = c(10, 99)){

  # Check if the data object is in the right format
  if (!inherits(data, "list") && !grepl("birdnet", names(data)[[2]]) && !grepl("main", names(data))[[1]]) {
    stop("The input should be the output of the `wt_download_report()` function with the argument `reports=c('main', 'birdnet')`")
  }

  #Check if the project has the correct transcription method for evaluation method chosen
  method <- data[[2]]$task_method[1]
  if(method=="NONE"){
    stop("The `wt_evaluate_classifier()` function only works on recordings processed with the '1SPT' or '1SPM' methods")
  }
  if(method=="1SPT" & resolution=="minute"){
    stop("You can only evaluate at the minute resolution for recordings that have been processed with the '1SPM' method")
  }

  #Get the classifier report and filter species as requested
  if(remove_species==TRUE){
    class <- data[[1]] |>
      dplyr::filter(is_species_allowed_in_project==TRUE)
  } else {
    class <- data[[1]]
  }

  #Summarize the classifier report to the requested resolution
  if(resolution=="task"){
    detections <- class |>
      dplyr::inner_join(data[[2]] |> dplyr::select(recording_id, task_id, task_duration), by = c("recording_id" = "recording_id")) |>
      dplyr::filter(!start_s > task_duration) |>
      group_by(project_id, location_id, recording_id, species_code) |>
      summarize(confidence = max(confidence), .groups="keep") |>
      ungroup() |>
      mutate(classifier = 1)
  }

  if(resolution=="minute"){
    detections <- class |>
      mutate(minute = ifelse(start_s==0, 1, ceiling(start_s/60))) |>
      group_by(project_id, location_id, recording_id, species_code, minute) |>
      summarize(confidence = max(confidence), .groups="keep") |>
      ungroup() |>
      mutate(classifier = 1)
  }

  if(resolution=="recording"){
    detections <- class |>
      group_by(project_id, location_id, recording_id, species_code) |>
      summarize(confidence = max(confidence),  .groups="keep") |>
      ungroup() |>
      mutate(classifier = 1)
  }

  #Tidy up the main report
  if(resolution=="task"){
    main <- wt_tidy_species(data[[2]], remove=c("mammal", "amphibian", "abiotic", "insect", "human", "unknown")) |>
      dplyr::select(project_id, location_id, recording_id, task_id, species_code) |>
      unique() |>
      mutate(human = 1)
  }

  if(resolution=="minute"){
    main <- wt_tidy_species(data[[2]], remove=c("mammal", "amphibian", "abiotic", "insect", "human", "unknown")) |>
      mutate(minute = ifelse(start_s==0, 1, ceiling(start_s/60))) |>
      dplyr::select(project_id, location_id, recording_id, species_code, minute) |>
      unique() |>
      mutate(human = 1)
  }

  if(resolution=="recording"){
    main <- wt_tidy_species(data[[2]], remove=c("mammal", "amphibian", "abiotic", "insect", "human", "unknown")) |>
      dplyr::select(project_id, location_id, recording_id, species_code) |>
      unique() |>
      mutate(human = 1)
  }

  #Join together
  both <- full_join(detections, main, by=c("project_id", "location_id", "recording_id", "species_code")) |>
    mutate(human = ifelse(is.na(human), 0, 1),
           classifier = ifelse(is.na(classifier), 0, 1),
           tp = ifelse(classifier==1 & human==1, 1, 0),
           fp = ifelse(classifier==1 & human==0, 1, 0),
           fn = ifelse(classifier==0 & human==1, 1, 0))

  #Filter to just species of interest if requested
  if(!is.null(species)){
    both <- dplyr::filter(both, species_code %in% species)
  }

  #Total number of human detections
  human_total <- sum(both$human, na.rm=TRUE)

  #Make threshold vector
  threshold <- seq(thresholds[1], thresholds[2], 1)

  #Calculate metrics
  prf <- do.call(rbind, lapply(X=threshold, FUN=.wt_calculate_prf, data=both, human_total=human_total))

  #return metrics
  return(prf)

}

#' Identify optimal threshold
#'
#' @description Retrieves the score threshold that maximizes F-score, which is a trade-off between precision and recall.
#'
#' @param data Tibble output from the `wt_evaluate_classifier()` function.
#'
#' @import dplyr
#' @export
#'
#' @examples
#' \dontrun{
#' data <- wt_download_report(project_id = 1144, sensor_id = "ARU",
#' reports = c("main", "birdnet"), weather_cols = FALSE)
#'
#' eval <- wt_evaluate_classifier(data, resolution = "recording",
#' remove_species = TRUE, thresholds = c(10, 99))
#'
#' threshold_use <- wt_classifier_threshold(eval) |> print()
#' }
#'
#' @return A single numeric value

wt_classifier_threshold <- function(data){

  # Filter to highest F-score
  highest_fscore <- data |>
    mutate(fscore = round(fscore, 2)) |>
    dplyr::filter(fscore == max(fscore, na.rm = TRUE))

  # Return the highest threshold of highest F-score as a single numeric value
  return(as.numeric(max(highest_fscore$threshold)))
}


#' Find additional species
#'
#' @description Check for species reported by BirdNET that the human listeners did not detect in our project.
#'
#' @param data Output from the `wt_download_report()` function when you request the `main` and `birdnet` reports
#' @param remove_species Logical; indicates whether species that are not allowed in the WildTrax project should be removed from the BirdNET report
#' @param threshold Numeric; the desired score threshold
#' @param resolution Character; either "recording" to identify any new species for each recording or "location" to identify new species for each location
#' @param format_to_tags Logical; when TRUE, creates a formatted output to turn detections into tags for uploading to WildTrax
#' @param output Character; when a valid directory is entered, exports the additional detections as tags for sync with a WildTrax project
#'
#' @import dplyr
#' @importFrom readr write_csv
#' @export
#'
#' @examples
#' \dontrun{
#' data <- wt_download_report(project_id = 1144, sensor_id = "ARU",
#' reports = c("main", "birdnet"), weather_cols = FALSE)
#'
#' new <- wt_additional_species(data, remove_species = TRUE,
#' threshold = 80, resolution="location")
#' }
#'
#' @return A tibble with the same fields as the `birdnet` report with the highest scoring detection for each new species detection in each recording.

wt_additional_species <- function(data, remove_species = TRUE, threshold = 50, resolution="task", format_to_tags = FALSE, output = NULL){

  # Check if the data object is in the right format
  if (!inherits(data, "list") && !grepl("birdnet", names(data)[[2]]) && !grepl("main", names(data))[[1]]) {
    stop("The input should be the output of the `wt_download_report()` function with the argument `reports=c('main', 'birdnet')`")
  }

  #Get the classifier report and filter species as requested
  if(remove_species==TRUE){
    class <- data[[1]] |>
      dplyr::filter(is_species_allowed_in_project==TRUE)
  } else {
    class <- data[[1]]
  }

  #Summarize the reports and put together at the desired resolution

  #Create a join between task and recording
  classed <- class |>
    dplyr::inner_join(data[[2]] |> dplyr::select(recording_id, task_id, task_duration), by = c("recording_id" = "recording_id"), relationship = "many-to-many")

  if(resolution=="task"){

    #Classifier report
    detections <- class |>
      dplyr::filter(confidence >= threshold) |>
      dplyr::inner_join(data[[2]] |> dplyr::select(recording_id, task_id, task_duration), by = c("recording_id" = "recording_id"), relationship = "many-to-many") |>
      dplyr::filter(!start_s > task_duration) |>
      dplyr::group_by(project_id, location_id, recording_id, task_id, species_code) |>
      dplyr::summarize(confidence = max(confidence),  .groups="keep") |>
      dplyr::ungroup()

    #Main report
    main <- wt_tidy_species(data[[2]], remove=c("mammal", "amphibian", "abiotic", "insect", "human", "unknown")) |>
      dplyr::select(project_id, location_id, recording_id, task_id, species_code) |>
      dplyr::distinct()

    #Put together
    new <- dplyr::anti_join(detections, main, by=c("project_id", "location_id", "recording_id", "task_id", "species_code")) |>
      dplyr::left_join(classed, by=c("project_id", "location_id", "recording_id", "task_id", "species_code", "confidence"), multiple="all")
    if (nrow(new) == 0) {
      stop("There were no additional species detected.")
    } else {
      new <- new |>
        dplyr::group_by(project_id, location_id, recording_id,task_id, species_code, confidence) |>
        dplyr::sample_n(1) |>
        dplyr::ungroup()
    }
  }


  if(resolution=="recording"){

    #Classifier report
    detections <- class |>
      dplyr::filter(confidence >= threshold) |>
      dplyr::group_by(project_id, location_id, recording_id, species_code) |>
      dplyr::summarize(confidence = max(confidence),  .groups="keep") |>
      dplyr::ungroup()

    #Main report
    main <- wt_tidy_species(data[[2]], remove=c("mammal", "amphibian", "abiotic", "insect", "human", "unknown")) |>
      dplyr::select(project_id, location_id, recording_id, species_code) |>
      dplyr::distinct()

    #Put together
    new <- dplyr::anti_join(detections, main, by=c("project_id", "location_id", "recording_id", "species_code")) |>
      dplyr::left_join(class, by=c("project_id", "location_id", "recording_id", "species_code", "confidence"), multiple="all") |>
      dplyr::group_by(project_id, location_id, recording_id, species_code, confidence) |>
      dplyr::sample_n(1) |>
      dplyr::ungroup()

  }

  if(resolution=="location"){

    #Classifier report
    detections <- class |>
      dplyr::filter(confidence >= threshold) |>
      dplyr::group_by(project_id, location_id, species_code) |>
      dplyr::summarize(confidence = max(confidence),  .groups="keep") |>
      dplyr::ungroup()

    #Main report
    main <- wt_tidy_species(data[[2]], remove=c("mammal", "amphibian", "abiotic", "insect", "human", "unknown")) |>
      dplyr::select(project_id, location_id, species_code) |>
      dplyr::distinct()

    #Put together
    new <- anti_join(detections, main, by=c("project_id", "location_id", "species_code")) |>
      dplyr::left_join(class, by=c("project_id", "location_id", "species_code", "confidence"), multiple="all") |>
      dplyr::group_by(project_id, location_id, species_code, confidence) |>
      dplyr::sample_n(1) |>
      dplyr::ungroup()

  }

  if(resolution=="project"){

    #Classifier report
    detections <- class |>
      dplyr::filter(confidence >= threshold) |>
      dplyr::group_by(project_id, species_code) |>
      dplyr::summarize(confidence = max(confidence),  .groups="keep") |>
      dplyr::ungroup()

    #Main report
    main <- wt_tidy_species(data[[2]], remove=c("mammal", "amphibian", "abiotic", "insect", "human", "unknown")) |>
      dplyr::select(project_id, species_code) |>
      dplyr::distinct()

    #Put together
    new <- anti_join(detections, main, by=c("project_id", "species_code")) |>
      dplyr::left_join(class, by=c("project_id", "species_code", "confidence"), multiple="all") |>
      dplyr::group_by(project_id, species_code, confidence) |>
      dplyr::sample_n(1) |>
      dplyr::ungroup()

  }

  return(new)

  if(format_to_tags == TRUE & dir.exists(output) & !is.null(output)){

    if(resolution!="task"){
      message("Currently tag uploads are best supported when you resolve at the task level. You may encounter an error otherwise. If you used `wt_additional_species(resolution='recording')` change the task lengths to the maximum length of the recording in your project")
    }

    ### Fields in WildTrax Sync will be updated in Vue3, or in Vue2 if there's high and urgent user demand. ###

    new_export <- new |>
      dplyr::relocate(location) |>
      dplyr::relocate(recording_date_time, .after = location) |>
      dplyr::rename("recordingDate" = 2) |>
      dplyr::inner_join(data[[2]] |> select(task_id, task_method) |> distinct(), by = "task_id") |>
      dplyr::relocate(task_method, .after = recordingDate) |>
      dplyr::rename("method" = 3) |>
      dplyr::relocate(task_duration, .after = method) |>
      dplyr::rename("taskLength" = 4) |>
      dplyr::mutate(transcriber = "birdnet") |>
      dplyr::relocate(transcriber, .after = taskLength) |>
      dplyr::relocate(species_code, .after = transcriber) |>
      dplyr::rename("species" = 6) |>
      dplyr::arrange(species, start_s) |>
      dplyr::group_by(location, recordingDate, species) |>
      dplyr::mutate(speciesIndividualNumber = row_number()) |>
      dplyr::ungroup() |>
      dplyr::relocate(speciesIndividualNumber, .after = species) |>
      dplyr::mutate(vocalization = "SONG") |>
      dplyr::relocate(vocalization, .after = speciesIndividualNumber) |>
      dplyr::mutate(abundance = 1) |>
      dplyr::relocate(abundance, .after = vocalization) |>
      dplyr::relocate(start_s, .after = abundance) |>
      dplyr::rename("startTime" = 10) |>
      dplyr::mutate(tagLength = "") |>
      dplyr::relocate(tagLength, .after = startTime) |>
      dplyr::mutate(minFreq = "") |>
      dplyr::mutate(maxFreq = "") |>
      dplyr::mutate(speciesIndividualComment = confidence) |>
      dplyr::mutate(internal_tag_id = "") |>
      dplyr::relocate(minFreq:internal_tag_id, .after = tagLength) |>
      dplyr::filter(!startTime > taskLength) |>
      dplyr::select(1:internal_tag_id) |>
      readr::write_csv(paste0(output,"/birdnet_tags.csv"))
  }
}
